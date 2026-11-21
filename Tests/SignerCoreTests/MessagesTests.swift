import XCTest
@testable import SignerCore

final class MessagesTests: XCTestCase {
    func testDecodeGetInfoRequest() throws {
        let json = #"{"operation":"GET_INFO","input":{"sbSession":"s","host":"eporezi.purs.gov.rs","language":"sr-Cyrl-RS"}}"#
        let req = try JSONDecoder().decode(Request.self, from: Data(json.utf8))
        XCTAssertEqual(req.operation, .getInfo)
        guard case .getInfo(let input) = req.input else { return XCTFail("wrong input") }
        XCTAssertEqual(input.sbSession, "s")
        XCTAssertEqual(input.host, "eporezi.purs.gov.rs")
        XCTAssertEqual(input.language, "sr-Cyrl-RS")
    }

    func testEncodeProvidersEnvelope() throws {
        struct Providers: Codable { let providers: [String] }
        let env = Envelope(operation: .getProviders, status: .ok, payload: Providers(providers: []))
        let data = try JSONEncoder().encode(env)
        let got = try JSONSerialization.jsonObject(with: data) as? NSDictionary
        let want = try JSONSerialization.jsonObject(with: Data(#"{"operation":"GET_PROVIDERS","status":0,"payload":{"providers":[]}}"#.utf8)) as? NSDictionary
        XCTAssertEqual(got, want)
        XCTAssertTrue(got?["status"] is NSNumber)
    }

    func testDecodeSignedXmlInput() throws {
        let json = #"{"operation":"GET_SIGNED_XML","input":{"certificate":{"alias":"a","name":"n"},"pin":"1234","xml":"<x/>"}}"#
        let req = try JSONDecoder().decode(Request.self, from: Data(json.utf8))
        XCTAssertEqual(req.operation, .getSignedXml)
        guard case .getSignedXml(let input) = req.input else { return XCTFail("wrong input") }
        XCTAssertEqual(input.certificate, Alias(alias: "a", name: "n"))
        XCTAssertEqual(input.xml, "<x/>")
        XCTAssertEqual(input.pin.bytes, Array("1234".utf8))
    }

    func testDecodeCertificatesAndTerminalsInput() throws {
        let c = try JSONDecoder().decode(GetCertificatesInput.self, from: Data(#"{"pin":"9","terminalId":2}"#.utf8))
        XCTAssertEqual(c.terminalId, 2)
        let t = try JSONDecoder().decode(GetTerminalsInput.self, from: Data(#"{"providerId":1}"#.utf8))
        XCTAssertEqual(t.providerId, 1)
    }

    func testStatusEncodesBareInt() throws {
        let data = try JSONEncoder().encode([Status(1200)])
        XCTAssertEqual(String(data: data, encoding: .utf8), "[1200]")
    }

    func testRequestWithoutInput() throws {
        let req = try JSONDecoder().decode(Request.self, from: Data(#"{"operation":"ON_OPEN_EVENT"}"#.utf8))
        XCTAssertEqual(req.operation, .onOpenEvent)
        if case .none = req.input {} else { XCTFail("expected none") }
    }

}
