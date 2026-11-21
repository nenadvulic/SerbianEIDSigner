import XCTest
@testable import SignerCore

final class DispatcherTests: XCTestCase {
    private func json(_ d: Data?) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(d)) as? [String: Any])
    }
    private func request(_ s: String) throws -> Request {
        try JSONDecoder().decode(Request.self, from: Data(s.utf8))
    }

    func testOnOpen() throws {
        var out: Data?
        Dispatcher(card: StubCardService()).onOpen { out = $0 }
        let j = try json(out)
        XCTAssertEqual(j["operation"] as? String, "ON_OPEN_EVENT")
        XCTAssertEqual(j["status"] as? Int, 0)
        let p = try XCTUnwrap(j["payload"] as? [String: Any])
        XCTAssertEqual(p["appName"] as? String, "SmartBox")
        XCTAssertEqual(p["appVersion"] as? String, "2.0.0")
        XCTAssertEqual(p["appBuild"] as? Int, 1)
        XCTAssertNotNil(p["osName"] as? String)
    }

    func testGetInfo() throws {
        let r = try request(#"{"operation":"GET_INFO","input":{"sbSession":"s","host":"h","language":"sr"}}"#)
        let j = try json(try respond(Dispatcher(card: StubCardService()), r).data)
        XCTAssertEqual(j["operation"] as? String, "GET_INFO")
        XCTAssertEqual(j["status"] as? Int, 0)
        XCTAssertEqual((j["payload"] as? [String: Any])?.count, 0)
    }

    func testGetProviders() throws {
        let r = try request(#"{"operation":"GET_PROVIDERS"}"#)
        let j = try json(try respond(Dispatcher(card: StubCardService()), r).data)
        XCTAssertEqual(j["operation"] as? String, "GET_PROVIDERS")
        XCTAssertEqual(j["status"] as? Int, 0)
        let ps = try XCTUnwrap((j["payload"] as? [String: Any])?["providers"] as? [[String: Any]])
        XCTAssertEqual(ps.first?["name"] as? String, "MUP")
        XCTAssertEqual(ps.first?["id"] as? Int, 1)
    }
}
