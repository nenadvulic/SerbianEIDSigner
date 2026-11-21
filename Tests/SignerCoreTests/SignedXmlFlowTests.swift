import XCTest
@testable import SignerCore

final class SignedXmlFlowTests: XCTestCase {
    private static func b64(_ s: String) -> String { Data(s.utf8).base64EncodedString() }
    private func makeReq(_ rawXml: String) -> String {
        #"{"operation":"GET_SIGNED_XML","input":{"certificate":{"alias":"b2","name":"Sig"},"pin":"1234","xml":"\#(Self.b64(rawXml))"}}"#
    }
    private lazy var req = makeReq("<doc><a>1</a></doc>")

    private func decodedPayload(_ j: [String: Any]) throws -> String {
        let obj = try XCTUnwrap(j["payload"] as? [String: Any])
        let b = try XCTUnwrap(obj["xml"] as? String)
        return String(decoding: try XCTUnwrap(Data(base64Encoded: b), "payload.xml not base64"), as: UTF8.self)
    }

    private func run(_ stub: StubCardService, request: String? = nil) throws -> (json: [String: Any], onMain: Bool) {
        let r = try JSONDecoder().decode(Request.self, from: Data((request ?? req).utf8))
        let (data, onMain) = try respond(Dispatcher(card: stub), r)
        return (try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any]), onMain)
    }

    func testSignedXmlMatchesProfileAndStubSignature() throws {
        let stub = StubCardService()
        let j = try run(stub).json
        XCTAssertEqual(j["operation"] as? String, "GET_SIGNED_XML")
        XCTAssertEqual(j["status"] as? Int, 0)
        let xml = try decodedPayload(j)
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

    func testRealPortalShapeBase64WithDeclarationAndNamespacedRoot() throws {
        let raw = #"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns2:Root xmlns:ns2="urn:x"><a>1</a></ns2:Root>"#
        let stub = StubCardService()
        let j = try run(stub, request: makeReq(raw)).json
        XCTAssertEqual(j["status"] as? Int, 0)
        let xml = try decodedPayload(j)
        XCTAssertTrue(xml.contains("ns2:Root"), xml)
        XCTAssertTrue(xml.contains("<SignatureValue>\(stub.signBytes.base64EncodedString())</SignatureValue>"), xml)
    }

    func testInvalidBase64IsGenericError() throws {
        let bad = req.replacingOccurrences(of: Self.b64("<doc><a>1</a></doc>"), with: "!!notbase64!!")
        XCTAssertEqual(try run(StubCardService(), request: bad).json["status"] as? Int, 1500)
    }

    func testOneSigningOperationUsesOneCardSession() throws {
        let stub = StubCardService()
        _ = try run(stub)
        XCTAssertEqual(stub.sessionCount.value, 1)
    }

    func testCardWorkRunsOffTheCallerThread() throws {
        XCTAssertFalse(try run(StubCardService()).onMain)
    }

    func testPinErrorsMapToStatus() throws {
        var stub = StubCardService()
        stub.signError = .pinIncorrect
        XCTAssertEqual(try run(stub).json["status"] as? Int, 1440)
        stub.signError = .pinLocked
        XCTAssertEqual(try run(stub).json["status"] as? Int, 1441)
        stub.signError = .generic
        XCTAssertEqual(try run(stub).json["status"] as? Int, 1500)
        stub.signError = nil
        stub.signCertError = .pinIncorrect
        XCTAssertEqual(try run(stub).json["status"] as? Int, 1440)
    }

    func testMalformedXmlIsGenericError() throws {
        XCTAssertEqual(try run(StubCardService(), request: makeReq("<doc>")).json["status"] as? Int, 1500)
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
