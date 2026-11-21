import XCTest
@testable import SignerCore

private func tlv(_ t: UInt8, _ b: [UInt8]) -> [UInt8] { [t, UInt8(b.count)] + b }

private func rdn(_ oid: [UInt8], _ v: String) -> [UInt8] {
    tlv(0x31, tlv(0x30, tlv(0x06, oid) + tlv(0x0C, Array(v.utf8))))
}

final class CertificateInfoTests: XCTestCase {
    func testIssuerAndSerialOfFixture() throws {
        let info = try CertificateInfo(der: PKCS15Fixtures.certSignature)
        XCTAssertEqual(info.issuer, "CN=Test Signature")
        XCTAssertEqual(info.serial, Data(base64Encoded: "TB1QUw23+QL1lhTAtxiEgsWUzVo="))
    }

    func testMultiRDNIssuerIsRFC2253Reversed() throws {
        let name = tlv(0x30, rdn([0x55, 4, 6], "RS") + rdn([0x55, 4, 10], "A,B") + rdn([0x55, 4, 3], "Root"))
        let tbs = tlv(0x30,
            tlv(0xA0, tlv(0x02, [2])) + tlv(0x02, [0x00, 0x80]) + tlv(0x30, tlv(0x06, [1])) + name)
        let cert = tlv(0x30, tbs)
        let info = try CertificateInfo(der: Data(cert))
        XCTAssertEqual(info.issuer, "CN=Root,O=A\\,B,C=RS")
        XCTAssertEqual(info.serial, Data([0x00, 0x80]))
    }

    func testGarbageThrows() {
        XCTAssertThrowsError(try CertificateInfo(der: Data([1, 2, 3])))
    }

    func testSubjectOfFixture() throws {
        let info = try CertificateInfo(der: PKCS15Fixtures.certSignature)
        XCTAssertEqual(info.subject, "CN=Test Signature")
    }

    func testHolderNameFromCraftedSubject() throws {
        let subject = tlv(0x30,
            rdn([0x55, 4, 5], "123") + rdn([0x55, 4, 4], "PETROVIĆ")
            + rdn([0x55, 4, 42], "PETAR") + rdn([0x55, 4, 3], "PETAR PETROVIĆ"))
        let tbs = tlv(0x30,
            tlv(0xA0, tlv(0x02, [2])) + tlv(0x02, [0x01]) + tlv(0x30, tlv(0x06, [1]))
            + tlv(0x30, rdn([0x55, 4, 3], "Issuer"))
            + tlv(0x30, [])
            + subject)
        let info = try CertificateInfo(der: Data(tlv(0x30, tbs)))
        XCTAssertEqual(info.holderName, "PETAR PETROVIĆ")
    }

    func testHolderNameGivenSurname() {
        XCTAssertEqual(
            CertificateInfo.holderName(fromSubjectAttributes: [([0x55, 4, 42], "Petar "), ([0x55, 4, 4], " Petrović")]),
            "Petar Petrović")
    }

    func testHolderNameCNWithJMBGPattern() {
        XCTAssertEqual(
            CertificateInfo.holderName(fromSubjectAttributes: [([0x55, 4, 3], "PETAR PETROVIĆ 1234567890123-1234567890123, SRB")]),
            "PETAR PETROVIĆ")
    }

    func testHolderNamePlainCNFallback() {
        XCTAssertEqual(
            CertificateInfo.holderName(fromSubjectAttributes: [([0x55, 4, 3], "Petar Petrović")]),
            "Petar Petrović")
    }

    func testHolderNameEmptyWhenNothingUsable() {
        XCTAssertEqual(CertificateInfo.holderName(fromSubjectAttributes: [([0x55, 4, 10], "Org")]), "")
    }
}
