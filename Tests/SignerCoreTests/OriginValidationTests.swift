import XCTest
@testable import SignerCore

private final class NoopHandler: MessageHandler {
    func onOpen(send: @escaping (Data) -> Void) {}
    func handle(_ request: Request, send: @escaping (Data) -> Void) {}
}

final class OriginValidationTests: XCTestCase {
    private let allowed = "https://eporezi.purs.gov.rs"

    private func statusLine(port: Int, origin: String?) throws -> String {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var tv = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        XCTAssertEqual(rc, 0)
        var req = "GET / HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        if let origin { req += "Origin: \(origin)\r\n" }
        req += "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        _ = req.withCString { send(fd, $0, strlen($0), 0) }
        var buf = [UInt8](repeating: 0, count: 1024)
        let n = recv(fd, &buf, buf.count, 0)
        XCTAssertGreaterThan(n, 0, "no response")
        let text = String(decoding: buf[0..<max(n, 0)], as: UTF8.self)
        return text.components(separatedBy: "\r\n").first ?? ""
    }

    private func run(origin: String?) throws -> String {
        let server = WebSocketServer(ports: [try freeLoopbackPort()], originAllowlist: [allowed], handler: NoopHandler())
        let port = try server.start()
        defer { server.stop() }
        return try statusLine(port: port, origin: origin)
    }

    func testAllowedOriginUpgrades() throws {
        XCTAssertTrue(try run(origin: allowed).contains("101"))
    }

    func testForeignOriginGets403() throws {
        let line = try run(origin: "https://evil.example")
        XCTAssertTrue(line.contains("403"), line)
        XCTAssertFalse(line.contains("101"))
    }

    func testMissingOriginGets403() throws {
        let line = try run(origin: nil)
        XCTAssertTrue(line.contains("403"), line)
    }
}
