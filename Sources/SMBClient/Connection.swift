import Foundation
import Network

public class Connection {
  let host: String
  var onDisconnected: (Error) -> Void

  private let connection: NWConnection
  private var buffer = Data()

  // Track pending requests by message ID
  private var pendingRequests: [UInt64: CheckedContinuation<Data, Error>] = [:]
  private let requestsLock = NSLock()

  // Flag to track if receive loop is running
  private var isReceiving = false

  public var state: NWConnection.State {
    connection.state
  }

  public init(host: String, port: Int = 445) {
    self.host = host
    let endpoint = NWEndpoint.hostPort(
      host: NWEndpoint.Host(host),
      port: NWEndpoint.Port(rawValue: UInt16(port))!
    )
    connection = NWConnection(to: endpoint, using: .tcp)
    onDisconnected = { _ in }
  }

  public func connect() async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      connection.stateUpdateHandler = { (state) in
        switch state {
        case .setup, .preparing:
          break
        case .waiting(let error):
          continuation.resume(throwing: error)
          self.connection.stateUpdateHandler = nil
        case .ready:
          continuation.resume()
          self.connection.stateUpdateHandler = stateUpdateHandler
          // Start continuous receive loop
          self.startReceiveLoop()
        case .failed(let error):
          continuation.resume(throwing: error)
          self.connection.stateUpdateHandler = nil
        case .cancelled:
          continuation.resume(throwing: ConnectionError.cancelled)
          self.connection.stateUpdateHandler = nil
        @unknown default:
          break
        }
      }

      connection.start(queue: .global(qos: .userInitiated))
    }

    @Sendable
    func stateUpdateHandler(_ state: NWConnection.State) {
      switch state {
      case .waiting(let error), .failed(let error):
        onDisconnected(error)
      case .setup, .preparing, .ready, .cancelled:
        break
      @unknown default:
        break
      }
    }
  }

  public func disconnect() {
    connection.cancel()
  }

  public func send(_ data: Data) async throws -> Data {
    switch connection.state {
    case .setup:
      try await connect()
    case .waiting(let error), .failed(let error):
      onDisconnected(error)
      throw error
    case .preparing, .ready:
      // Ensure receive loop is running
      startReceiveLoop()
    case .cancelled:
      throw ConnectionError.cancelled
    @unknown default:
      throw ConnectionError.unknown
    }

    // Extract message ID from the SMB2 header
    let reader = ByteReader(data)
    let header: Header = reader.read()
    let messageId = header.messageId

    let transportPacket = DirectTCPPacket(smb2Message: data)
    let content = transportPacket.encoded()

    return try await withCheckedThrowingContinuation { (continuation) in
      // Register the pending request
      requestsLock.lock()
      pendingRequests[messageId] = continuation
      requestsLock.unlock()

      connection.send(
        content: content,
        completion: .contentProcessed { (error) in
          if let error {
            // Remove pending request and resume with error
            self.requestsLock.lock()
            let cont = self.pendingRequests.removeValue(forKey: messageId)
            self.requestsLock.unlock()
            cont?.resume(throwing: error)
          }
          // If send succeeds, the response will be handled by the receive loop
        })
    }
  }

  private func startReceiveLoop() {
    requestsLock.lock()
    guard !isReceiving else {
      requestsLock.unlock()
      return
    }
    isReceiving = true
    requestsLock.unlock()

    Task {
      await receiveLoop()
    }
  }

  // Async wrapper for NWConnection.receive - writes data directly to buffer
  private func receiveData(minimumLength: Int = 0, maximumLength: Int = 65536) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      connection.receive(
        minimumIncompleteLength: minimumLength,
        maximumLength: maximumLength
      ) { (data, _, isComplete, error) in
        if let error = error {
          continuation.resume(throwing: error)
          return
        }

        guard let data = data else {
          let err = isComplete ? ConnectionError.disconnected : ConnectionError.noData
          continuation.resume(throwing: err)
          return
        }

        self.buffer.append(data)
        continuation.resume()
      }
    }
  }

  // Receive exactly byteCount bytes from buffer (reading more from network if needed)
  private func receiveExact(_ byteCount: Int) async throws -> Data {
    while buffer.count < byteCount {
      try await receiveData()
    }

    let data = Data(buffer.prefix(byteCount))
    buffer = Data(buffer.suffix(from: byteCount))
    return data
  }

  private func receiveLoop() async {
    while true {
      do {
        try await receiveAndProcessNextMessage()
      } catch {
        // Connection error, fail all pending requests
        failAllPendingRequests(with: error)
        return
      }
    }
  }

  private func receiveAndProcessNextMessage() async throws {
    // Receive exactly 4 bytes for the transport header
    let transportHeader = try await receiveExact(4)

    // Manually parse the length from the transport header
    // DirectTCP header: 1 byte zero + 3 bytes length (big-endian)
    let length =
      Int(transportHeader[1]) << 16 | Int(transportHeader[2]) << 8 | Int(transportHeader[3])

    // Receive exactly the SMB message bytes
    let messageData = try await receiveExact(length)

    let reader = ByteReader(messageData)
    let header: Header = reader.read()
    let messageId = header.messageId
    // print("Received SMB response for message ID: \(messageId)")

    // Process the SMB response
    dispatchResponse(messageId: messageId, result: .success(messageData))
  }

  private func dispatchResponse(messageId: UInt64, result: Result<Data, Error>) {
    requestsLock.lock()
    let continuation = pendingRequests.removeValue(forKey: messageId)
    requestsLock.unlock()

    if let continuation = continuation {
      switch result {
      case .success(let data):
        continuation.resume(returning: data)
      case .failure(let error):
        continuation.resume(throwing: error)
      }
    }
  }

  private func failAllPendingRequests(with error: Error) {
    requestsLock.lock()
    let requests = pendingRequests
    pendingRequests.removeAll()
    isReceiving = false
    requestsLock.unlock()

    for (_, continuation) in requests {
      continuation.resume(throwing: error)
    }
  }

}

public enum ConnectionError: Error {
  case noData
  case disconnected
  case cancelled
  case unknown
}
