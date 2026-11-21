import XCTest
import NIOCore
import NIOPosix
@testable import SignerCore

private final class OpenHandler: MessageHandler {
    func onOpen(send: @escaping (Data) -> Void) { send(Data("ON_OPEN_EVENT".utf8)) }
    func handle(_ request: Request, send: @escaping (Data) -> Void) {}
}

private final class ReplyHandler: MessageHandler {
    func onOpen(send: @escaping (Data) -> Void) {}
    func handle(_ request: Request, send: @escaping (Data) -> Void) { send(Data("REPLY_OK".utf8)) }
}

final class WebSocketServerTests: XCTestCase {
    func testBindsFirstFreePortOfList() throws {
        let g = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? g.syncShutdownGracefully() }
        let blocker = try ServerBootstrap(group: g).bind(host: "127.0.0.1", port: 0).wait()
        defer { try? blocker.close().wait() }
        let busy = blocker.localAddress!.port!
        let free = try freeLoopbackPort()

        let server = WebSocketServer(ports: [busy, free], originAllowlist: [], handler: OpenHandler())
        let bound = try server.start()
        defer { server.stop() }
        XCTAssertEqual(bound, free)
    }

    func testTwoConcurrentClientsEachGetOnOpen() async throws {
        let server = WebSocketServer(ports: [try freeLoopbackPort()], originAllowlist: ["https://eporezi.purs.gov.rs"], handler: OpenHandler())
        let port = try server.start()
        defer { server.stop() }

        let url = URL(string: "ws://127.0.0.1:\(port)")!
        var req = URLRequest(url: url)
        req.setValue("https://eporezi.purs.gov.rs", forHTTPHeaderField: "Origin")
        let t1 = URLSession.shared.webSocketTask(with: req)
        let t2 = URLSession.shared.webSocketTask(with: req)
        t1.resume(); t2.resume()
        defer { t1.cancel(with: .goingAway, reason: nil); t2.cancel(with: .goingAway, reason: nil) }

        for t in [t1, t2] {
            guard case .string(let s) = try await t.receive() else { return XCTFail("expected text") }
            XCTAssertEqual(s, "ON_OPEN_EVENT")
        }
    }

    private func assertOnOpen(host: String, port: Int) async throws {
        var req = URLRequest(url: URL(string: "ws://\(host):\(port)")!)
        req.setValue("https://eporezi.purs.gov.rs", forHTTPHeaderField: "Origin")
        let t = URLSession.shared.webSocketTask(with: req)
        t.resume()
        defer { t.cancel(with: .goingAway, reason: nil) }
        guard case .string(let s) = try await t.receive() else { return XCTFail("expected text") }
        XCTAssertEqual(s, "ON_OPEN_EVENT")
    }

    func testReachableViaLocalhostAndBothLoopbackFamilies() async throws {
        let server = WebSocketServer(ports: [try freeLoopbackPort()], originAllowlist: ["https://eporezi.purs.gov.rs"], handler: OpenHandler())
        let port = try server.start()
        defer { server.stop() }
        try await assertOnOpen(host: "localhost", port: port)
        try await assertOnOpen(host: "127.0.0.1", port: port)
        try await assertOnOpen(host: "[::1]", port: port)
    }

    func testMaskedClientMessageRoundTripsToServerResponse() async throws {
        let server = WebSocketServer(ports: [try freeLoopbackPort()], originAllowlist: ["https://eporezi.purs.gov.rs"], handler: ReplyHandler())
        let port = try server.start()
        defer { server.stop() }

        var req = URLRequest(url: URL(string: "ws://127.0.0.1:\(port)")!)
        req.setValue("https://eporezi.purs.gov.rs", forHTTPHeaderField: "Origin")
        req.timeoutInterval = 5
        let t = URLSession.shared.webSocketTask(with: req)
        t.resume()
        defer { t.cancel(with: .goingAway, reason: nil) }

        try await t.send(.string(#"{"operation":"GET_PROVIDERS"}"#))

        let watchdog = Task { try await Task.sleep(nanoseconds: 5_000_000_000); t.cancel(with: .goingAway, reason: nil) }
        defer { watchdog.cancel() }
        let reply = try await t.receive()
        guard case .string(let s) = reply else { return XCTFail("expected text") }
        XCTAssertEqual(s, "REPLY_OK")
    }
}
