import XCTest
import CryptoKit
@testable import SignerCore

final class XMLDSigTests: XCTestCase {
    func testC14NInclusiveFixture() throws {
        let xml = "<?xml version=\"1.0\"?>\n<a  xmlns:z=\"urn:z\"   b=\"1\"  ><z:c   y='2' x=\"3\"/>\n  <d>t &amp; <![CDATA[<u>]]></d></a>"
        let out = try XMLDSigBuilder.canonicalize(xml: xml)
        let expected = "<a xmlns:z=\"urn:z\" b=\"1\"><z:c x=\"3\" y=\"2\"></z:c>\n  <d>t &amp; &lt;u&gt;</d></a>"
        XCTAssertEqual(String(data: out, encoding: .utf8), expected)
    }

    func testBuildWithStubSigner() throws {
        let doc = "<Invoice xmlns=\"urn:inv\"> <id>1</id>\n</Invoice>"
        let cert = Data([1, 2, 3, 4, 5])
        let stub = Data([0xDE, 0xAD, 0xBE, 0xEF])
        var received: Data?
        let out = try XMLDSigBuilder().build(
            documentXML: doc, certDER: cert, issuer: "CN=Test & CA, O=X", serial: Data([0x01, 0x00]),
            subject: "SERIALNUMBER=PNORS-1234567890123,CN=Test Holder",
            sign: { received = $0; return stub })
        XCTAssertEqual(received?.count, 32)
        for uri in ["http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                    "http://www.w3.org/2001/04/xmlenc#sha256",
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"] {
            XCTAssertTrue(out.contains(uri), uri)
        }
        XCTAssertTrue(out.contains("URI=\"\""))
        XCTAssertTrue(out.contains("<X509IssuerName>CN=Test &amp; CA, O=X</X509IssuerName>"))
        XCTAssertTrue(out.contains("<X509SerialNumber>256</X509SerialNumber>"))
        XCTAssertTrue(out.contains("<X509Certificate>\(cert.base64EncodedString())</X509Certificate>"))
        XCTAssertTrue(out.contains("<X509SubjectName>SERIALNUMBER=PNORS-1234567890123,CN=Test Holder</X509SubjectName>"))

        let posCert = out.range(of: "<X509Certificate>")!.lowerBound
        let posIssuer = out.range(of: "<X509IssuerSerial>")!.lowerBound
        let posSubject = out.range(of: "<X509SubjectName>")!.lowerBound
        XCTAssertTrue(posCert < posIssuer && posIssuer < posSubject)
        XCTAssertTrue(out.contains("<SignatureValue>\(stub.base64EncodedString())</SignatureValue>"))

        let canon = try XMLDSigBuilder.canonicalize(xml: doc)
        let d = Data(SHA256.hash(data: canon)).base64EncodedString()
        XCTAssertTrue(out.contains("<DigestValue>\(d)</DigestValue>"))

        let sigRange = out.range(of: "<Signature")!
        XCTAssertTrue(out.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("</Signature></Invoice>"))
        XCTAssertTrue(sigRange.lowerBound > out.startIndex)

        let si = try XMLDSigBuilder.canonicalizeSignedInfo(inSignedXML: out)
        XCTAssertEqual(received, Data(SHA256.hash(data: si)))
    }

    func testEmptyDocumentThrows() {
        XCTAssertThrowsError(try XMLDSigBuilder().build(documentXML: "", certDER: Data(), issuer: "x", serial: Data([1]), sign: { $0 }))
    }

    func testSignedInfoGoldenInheritedNamespaces() throws {
        let doc = "<e:Invoice xmlns:e=\"urn:e\" xmlns=\"urn:def\"><e:Line xmlns:l=\"urn:l\" l:a=\"1\"/></e:Invoice>"
        let out = try XMLDSigBuilder().build(documentXML: doc, certDER: Data([1]), issuer: "I", serial: Data([1]), sign: { _ in Data([9]) })
        let got = String(data: try XMLDSigBuilder.canonicalizeSignedInfo(inSignedXML: out), encoding: .utf8)!
        let start = out.range(of: "<DigestValue>")!.upperBound
        let end = out.range(of: "</DigestValue>")!.lowerBound
        let dv = String(out[start..<end])
        let expected = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:e=\"urn:e\">"
            + "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>"
            + "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></SignatureMethod>"
            + "<Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform></Transforms>"
            + "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>"
            + "<DigestValue>\(dv)</DigestValue></Reference></SignedInfo>"
        XCTAssertEqual(got, expected)
    }
}
