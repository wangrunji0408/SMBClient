import Foundation
import Network

public actor Connection {
  public let host: String

  private let connection: NWConnection

  // Track pending requests by message ID
  private var pendingRequests: [UInt64: CheckedContinuation<Data, Error>] = [:]

  public nonisolated var state: NWConnection.State {
    connection.state
  }

  public init(host: String, port: Int = 445) {
    self.host = host
    let endpoint = NWEndpoint.hostPort(
      host: NWEndpoint.Host(host),
      port: NWEndpoint.Port(rawValue: UInt16(port))!
    )
    connection = NWConnection(to: endpoint, using: .tcp)
  }

  public func connect() async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      connection.stateUpdateHandler = { [weak self] (state) in
        switch state {
        case .setup, .preparing:
          break
        case .waiting(let error):
          continuation.resume(throwing: error)
          self?.connection.stateUpdateHandler = nil
        case .ready:
          Task {
            await self?.receiveLoop()
          }
          continuation.resume()
          self?.connection.stateUpdateHandler = nil
        case .failed(let error):
          continuation.resume(throwing: error)
          self?.connection.stateUpdateHandler = nil
        case .cancelled:
          continuation.resume(throwing: ConnectionError.cancelled)
          self?.connection.stateUpdateHandler = nil
        @unknown default:
          break
        }
      }
      connection.start(queue: .global(qos: .userInitiated))
    }
  }

  public nonisolated func disconnect() {
    connection.cancel()
  }

  public func send(_ data: Data) async throws -> Data {
    switch connection.state {
    case .setup:
      try await connect()
    case .waiting(let error), .failed(let error):
      throw error
    case .preparing, .ready:
      break
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
      pendingRequests[messageId] = continuation

      connection.send(
        content: content,
        completion: .contentProcessed { [weak self] (error) in
          if let error {
            // Remove pending request and resume with error
            Task {
              let cont = await self?.removePendingRequest(messageId: messageId)
              cont?.resume(throwing: error)
            }
          }
          // If send succeeds, the response will be handled by the receive loop
        })
    }
  }

  // Receive exactly byteCount bytes
  private func receiveExact(_ byteCount: Int) async throws -> Data {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
      connection.receive(
        minimumIncompleteLength: byteCount,
        maximumLength: byteCount
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

        continuation.resume(returning: data)
      }
    }
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

    guard messageData.count >= 64 else { return }
    let reader = ByteReader(messageData)
    let header: Header = reader.read()
    let messageId = header.messageId
    // print("Received SMB response for message ID: \(messageId), status: 0x\(String(header.status, radix: 16))")

    // Check if this is a pending response
    switch NTStatus(header.status) {
    case .success,
      .moreProcessingRequired,
      .noMoreFiles,
      .endOfFile:
      dispatchResponse(messageId: messageId, result: .success(messageData))
    case .pending:
      break
    default:
      dispatchResponse(messageId: messageId, result: .failure(ErrorResponse(data: messageData)))
    }
  }

  private func dispatchResponse(messageId: UInt64, result: Result<Data, Error>) {
    let continuation = pendingRequests.removeValue(forKey: messageId)

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
    let requests = pendingRequests
    pendingRequests.removeAll()

    for (_, continuation) in requests {
      continuation.resume(throwing: error)
    }
  }

  private func removePendingRequest(messageId: UInt64) -> CheckedContinuation<Data, Error>? {
    return pendingRequests.removeValue(forKey: messageId)
  }

}

public enum ConnectionError: Error {
  case noData
  case disconnected
  case cancelled
  case unknown
}
