import XCTest
@testable import SignerCore

final class SecretTests: XCTestCase {
    private let pin = "48151623"

    // COMPILE-TIME GUARANTEE: `Secret` must never conform to Encodable. Adding that conformance
    // would let a PIN flow into any Envelope/response. Do NOT add `extension Secret: Encodable`;
    // a check like `XCTAssertFalse((Secret(bytes: []) as Any) is Encodable)` guards it at runtime.
    func testSecretIsNotEncodable() {
        XCTAssertFalse((Secret(bytes: Array(pin.utf8)) as Any) is Encodable)
    }

    func testInterpolationAndReflectingRedacted() {
        let s = Secret(bytes: Array(pin.utf8))
        XCTAssertEqual("\(s)", "<redacted>")
        XCTAssertEqual(String(reflecting: s), "<redacted>")
        XCTAssertEqual(String(describing: s), "<redacted>")
    }

    func testDumpOfDecodedRequestsContainsNoPin() throws {
        let reqs = [
            #"{"operation":"GET_CERTIFICATES","input":{"pin":"\#(pin)","terminalId":2}}"#,
            #"{"operation":"GET_SIGNED_XML","input":{"certificate":{"alias":"a","name":"n"},"pin":"\#(pin)","xml":"<x/>"}}"#,
        ]
        for r in reqs {
            let req = try JSONDecoder().decode(Request.self, from: Data(r.utf8))
            var out = ""
            dump(req, to: &out)
            out += "\(req)" + String(reflecting: req)
            XCTAssertFalse(out.contains(pin), out)
        }
    }

    func testResponsesNeverContainPin() throws {
        var stub = StubCardService()
        stub.certList = [Alias(alias: "a1", name: "N")]
        var failing = StubCardService()
        failing.certError = .pinIncorrect
        failing.signError = .pinIncorrect
        let reqs = [
            #"{"operation":"GET_CERTIFICATES","input":{"pin":"\#(pin)","terminalId":2}}"#,
            #"{"operation":"GET_SIGNED_XML","input":{"certificate":{"alias":"b2","name":"Sig"},"pin":"\#(pin)","xml":"<doc><a>1</a></doc>"}}"#,
        ]
        for card in [stub, failing] {
            for r in reqs {
                let req = try JSONDecoder().decode(Request.self, from: Data(r.utf8))
                let data = try respond(Dispatcher(card: card), req).data
                XCTAssertFalse(String(decoding: data, as: UTF8.self).contains(pin))
            }
        }
    }

    func testZeroizeClearsBytes() {
        var a = Array(pin.utf8)
        Secret.zeroize(&a)
        XCTAssertEqual(a, [UInt8](repeating: 0, count: 8))
        var empty: [UInt8] = []
        Secret.zeroize(&empty)
    }
}
