import XCTest
import NIOCore
import NIOPosix
@testable import SignerCore

private final class OpenHandler: MessageHandler {
    func onOpen(send: @escaping (Data) -> Void) { send(Data("ON_OPEN_EVENT".utf8)) }
    func handle(_ request: Request, send: @escaping (Data) -> Void) {}
}

final class WebSocketServerTests: XCTestCase {
    private func freePort() throws -> Int {
        let g = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? g.syncShutdownGracefully() }
        let ch = try ServerBootstrap(group: g).bind(host: "127.0.0.1", port: 0).wait()
        let p = ch.localAddress!.port!
        try ch.close().wait()
        return p
    }

    func testBindsFirstFreePortOfList() throws {
        let g = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? g.syncShutdownGracefully() }
        let blocker = try ServerBootstrap(group: g).bind(host: "127.0.0.1", port: 0).wait()
        defer { try? blocker.close().wait() }
        let busy = blocker.localAddress!.port!
        let free = try freePort()

        let server = WebSocketServer(ports: [busy, free], originAllowlist: [], handler: OpenHandler())
        let bound = try server.start()
        defer { server.stop() }
        XCTAssertEqual(bound, free)
    }

    func testTwoConcurrentClientsEachGetOnOpen() async throws {
        let server = WebSocketServer(ports: [try freePort()], originAllowlist: [], handler: OpenHandler())
        let port = try server.start()
        defer { server.stop() }

        let url = URL(string: "ws://127.0.0.1:\(port)")!
        let t1 = URLSession.shared.webSocketTask(with: url)
        let t2 = URLSession.shared.webSocketTask(with: url)
        t1.resume(); t2.resume()
        defer { t1.cancel(with: .goingAway, reason: nil); t2.cancel(with: .goingAway, reason: nil) }

        for t in [t1, t2] {
            guard case .string(let s) = try await t.receive() else { return XCTFail("expected text") }
            XCTAssertEqual(s, "ON_OPEN_EVENT")
        }
    }
}
