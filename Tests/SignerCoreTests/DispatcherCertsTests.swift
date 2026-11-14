import XCTest
@testable import SignerCore

final class DispatcherCertsTests: XCTestCase {
    private func run(_ stub: StubCardService, _ s: String) throws -> [String: Any] {
        var out: Data?
        let r = try JSONDecoder().decode(Request.self, from: Data(s.utf8))
        Dispatcher(card: stub).handle(r) { out = $0 }
        return try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(out)) as? [String: Any])
    }
    private let terminalsReq = #"{"operation":"GET_TERMINALS","input":{"providerId":1}}"#
    private let certsReq = #"{"operation":"GET_CERTIFICATES","input":{"pin":"1234","terminalId":2}}"#

    func testGetTerminals() throws {
        var stub = StubCardService()
        stub.terminalList = [Terminal(id: 2, name: "Reader")]
        let j = try run(stub, terminalsReq)
        XCTAssertEqual(j["operation"] as? String, "GET_TERMINALS")
        XCTAssertEqual(j["status"] as? Int, 0)
        let t = try XCTUnwrap((j["payload"] as? [String: Any])?["terminals"] as? [[String: Any]])
        XCTAssertEqual(t.count, 1)
        XCTAssertEqual(t[0]["id"] as? Int, 2)
        XCTAssertEqual(t[0]["name"] as? String, "Reader")
    }

    func testGetTerminalsNoCardIsEmpty() throws {
        let j = try run(StubCardService(), terminalsReq)
        XCTAssertEqual(j["status"] as? Int, 0)
        let t = try XCTUnwrap((j["payload"] as? [String: Any])?["terminals"] as? [Any])
        XCTAssertTrue(t.isEmpty)
    }

    func testGetCertificates() throws {
        var stub = StubCardService()
        stub.certList = [Alias(alias: "a1", name: "Nenad")]
        let j = try run(stub, certsReq)
        XCTAssertEqual(j["operation"] as? String, "GET_CERTIFICATES")
        XCTAssertEqual(j["status"] as? Int, 0)
        let c = try XCTUnwrap((j["payload"] as? [String: Any])?["certificates"] as? [[String: Any]])
        XCTAssertEqual(c.count, 1)
        XCTAssertEqual(c[0]["alias"] as? String, "a1")
        XCTAssertEqual(c[0]["name"] as? String, "Nenad")
    }

    func testPinIncorrectMapsToStatus() throws {
        var stub = StubCardService()
        stub.certError = .pinIncorrect
        let j = try run(stub, certsReq)
        XCTAssertEqual(j["status"] as? Int, 1440)
    }

    func testPinLockedAndGenericMapToStatus() throws {
        var stub = StubCardService()
        stub.certError = .pinLocked
        XCTAssertEqual(try run(stub, certsReq)["status"] as? Int, 1441)
        stub.certError = .generic
        XCTAssertEqual(try run(stub, certsReq)["status"] as? Int, 1400)
    }

    func testTerminalErrorsMapToStatus() throws {
        var stub = StubCardService()
        stub.terminalError = .middleware
        XCTAssertEqual(try run(stub, terminalsReq)["status"] as? Int, 1350)
        stub.terminalError = .generic
        XCTAssertEqual(try run(stub, terminalsReq)["status"] as? Int, 1300)
    }
}
