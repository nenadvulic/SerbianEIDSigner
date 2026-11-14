import XCTest
@testable import SignerCore

struct StubCardService: CardService {
    var terminalList: [Terminal] = []
    var certList: [Alias] = []
    var certError: CardError?
    var terminalError: CardError?
    var signCertDER: Data = PKCS15Fixtures.certSignature
    var signCertError: CardError?
    var signBytes = Data([0xDE, 0xAD, 0xBE, 0xEF])
    var signError: CardError?
    func providers() -> [Provider] { [Provider(id: 1, name: "MUP")] }
    func terminals(providerId: Int) throws -> [Terminal] {
        if let e = terminalError { throw e }
        return terminalList
    }
    func certificates(providerId: Int, terminalId: Int, pin: Secret) throws -> [Alias] {
        if let e = certError { throw e }
        return certList
    }
    func signingCertificate(providerId: Int, terminalId: Int, alias: Alias, pin: Secret) throws -> Data {
        if let e = signCertError { throw e }
        return signCertDER
    }
    func sign(providerId: Int, terminalId: Int, alias: Alias, pin: Secret, canonicalSignedInfoSHA256: Data) throws -> Data {
        if let e = signError { throw e }
        return signBytes
    }
}

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
        var out: Data?
        let r = try request(#"{"operation":"GET_INFO","input":{"sbSession":"s","host":"h","language":"sr"}}"#)
        Dispatcher(card: StubCardService()).handle(r) { out = $0 }
        let j = try json(out)
        XCTAssertEqual(j["operation"] as? String, "GET_INFO")
        XCTAssertEqual(j["status"] as? Int, 0)
        XCTAssertEqual((j["payload"] as? [String: Any])?.count, 0)
    }

    func testGetProviders() throws {
        var out: Data?
        let r = try request(#"{"operation":"GET_PROVIDERS"}"#)
        Dispatcher(card: StubCardService()).handle(r) { out = $0 }
        let j = try json(out)
        XCTAssertEqual(j["operation"] as? String, "GET_PROVIDERS")
        XCTAssertEqual(j["status"] as? Int, 0)
        let ps = try XCTUnwrap((j["payload"] as? [String: Any])?["providers"] as? [[String: Any]])
        XCTAssertEqual(ps.first?["name"] as? String, "MUP")
        XCTAssertEqual(ps.first?["id"] as? Int, 1)
    }
}
