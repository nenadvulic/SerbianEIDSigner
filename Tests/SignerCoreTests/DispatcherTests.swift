import XCTest
@testable import SignerCore

final class TerminalRecorder {
    private let lock = NSLock()
    private var ids: [Int] = []
    func record(_ id: Int) { lock.lock(); ids.append(id); lock.unlock() }
    var recorded: [Int] { lock.lock(); defer { lock.unlock() }; return ids }
}

struct StubCardService: CardService {
    var terminalList: [Terminal] = []
    var certList: [Alias] = []
    var certError: CardError?
    var terminalError: CardError?
    var signCertDER: Data = PKCS15Fixtures.certSignature
    var signCertError: CardError?
    var signBytes = Data([0xDE, 0xAD, 0xBE, 0xEF])
    var signError: CardError?
    var recorder: TerminalRecorder?
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
        recorder?.record(terminalId)
        if let e = signCertError { throw e }
        return signCertDER
    }
    func sign(providerId: Int, terminalId: Int, alias: Alias, pin: Secret, canonicalSignedInfoSHA256: Data) throws -> Data {
        recorder?.record(terminalId)
        if let e = signError { throw e }
        return signBytes
    }
}

extension XCTestCase {
    /// Calls `handle` and waits for the single response; also reports whether `send` ran on the main thread.
    func respond(_ d: MessageHandler, _ r: Request) throws -> (data: Data, onMain: Bool) {
        let exp = expectation(description: "response")
        var out: Data?
        var onMain = true
        d.handle(r) { out = $0; onMain = Thread.isMainThread; exp.fulfill() }
        wait(for: [exp], timeout: 5)
        return (try XCTUnwrap(out), onMain)
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
