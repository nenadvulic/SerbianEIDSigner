import XCTest
@testable import SignerCore

final class SignedXmlFlowTests: XCTestCase {
    private let req = #"{"operation":"GET_SIGNED_XML","input":{"certificate":{"alias":"b2","name":"Sig"},"pin":"1234","xml":"<doc><a>1</a></doc>"}}"#

    private func run(_ stub: StubCardService, onThread: ((Bool) -> Void)? = nil) throws -> [String: Any] {
        let exp = expectation(description: "response")
        var out: Data?
        let r = try JSONDecoder().decode(Request.self, from: Data(req.utf8))
        Dispatcher(card: stub).handle(r) { out = $0; onThread?(Thread.isMainThread); exp.fulfill() }
        wait(for: [exp], timeout: 5)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(out)) as? [String: Any])
    }

    func testSignedXmlMatchesProfileAndStubSignature() throws {
        let stub = StubCardService()
        let j = try run(stub)
        XCTAssertEqual(j["operation"] as? String, "GET_SIGNED_XML")
        XCTAssertEqual(j["status"] as? Int, 0)
        let xml = try XCTUnwrap(j["payload"] as? String)
        XCTAssertTrue(xml.contains("<SignatureValue>\(stub.signBytes.base64EncodedString())</SignatureValue>"), xml)
        for uri in ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                    "http://www.w3.org/2001/04/xmlenc#sha256",
                    "http://www.w3.org/2000/09/xmldsig#enveloped-signature"] {
            XCTAssertTrue(xml.contains(uri), uri)
        }
        XCTAssertTrue(xml.contains(#"URI="""#))
        XCTAssertTrue(xml.contains("<X509IssuerSerial>"))
        XCTAssertTrue(xml.contains("<X509IssuerName>CN=Test Signature</X509IssuerName>"))
        XCTAssertTrue(xml.contains("<X509Certificate>\(PKCS15Fixtures.certSignature.base64EncodedString())</X509Certificate>"))
        XCTAssertTrue(xml.contains("<a>1</a>"))
    }

    func testOneSigningOperationUsesOneCardSession() throws {
        let stub = StubCardService()
        _ = try run(stub)
        XCTAssertEqual(stub.sessionCount.value, 1)
    }

    func testCardWorkRunsOffTheCallerThread() throws {
        var onMain: Bool?
        _ = try run(StubCardService(), onThread: { onMain = $0 })
        XCTAssertEqual(onMain, false)
    }

    func testPinErrorsMapToStatus() throws {
        var stub = StubCardService()
        stub.signError = .pinIncorrect
        XCTAssertEqual(try run(stub)["status"] as? Int, 1440)
        stub.signError = .pinLocked
        XCTAssertEqual(try run(stub)["status"] as? Int, 1441)
        stub.signError = .generic
        XCTAssertEqual(try run(stub)["status"] as? Int, 1500)
        stub.signError = nil
        stub.signCertError = .pinIncorrect
        XCTAssertEqual(try run(stub)["status"] as? Int, 1440)
    }

    func testMalformedXmlIsGenericError() throws {
        let exp = expectation(description: "r")
        var out: Data?
        let bad = req.replacingOccurrences(of: "<doc><a>1</a></doc>", with: "<doc>")
        Dispatcher(card: StubCardService()).handle(try JSONDecoder().decode(Request.self, from: Data(bad.utf8))) { out = $0; exp.fulfill() }
        wait(for: [exp], timeout: 5)
        let j = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(out)) as? [String: Any])
        XCTAssertEqual(j["status"] as? Int, 1500)
    }

    func testTerminalIsPerConnectionNotShared() throws {
        let recorder = TerminalRecorder()
        var stub = StubCardService()
        stub.recorder = recorder
        let server = Dispatcher(card: stub)
        let a = server.makeConnectionHandler()
        let b = server.makeConnectionHandler()
        func certs(_ t: Int) throws -> Request {
            try JSONDecoder().decode(Request.self, from: Data(#"{"operation":"GET_CERTIFICATES","input":{"pin":"1234","terminalId":\#(t)}}"#.utf8))
        }
        _ = try respond(a, certs(1))
        _ = try respond(b, certs(0))
        let signReq = try JSONDecoder().decode(Request.self, from: Data(req.utf8))
        let resp = try JSONSerialization.jsonObject(with: respond(a, signReq).data) as? [String: Any]
        XCTAssertEqual(resp?["status"] as? Int, 0)
        XCTAssertEqual(Set(recorder.recorded), [1], "A signs only on its own terminal 1")
        _ = try respond(b, signReq)
        XCTAssertEqual(recorder.recorded, [1, 0], "B signs on terminal 0")
    }
}
