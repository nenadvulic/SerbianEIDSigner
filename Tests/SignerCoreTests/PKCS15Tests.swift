import XCTest
import Compression
@testable import SignerCore

/// In-memory card (approach from SerbianEIDToken's PKICardTests, MIT): files by FID,
/// SELECT sets the current file, READ BINARY slices it.
private final class FileCard: APDUTransport {
    var files: [[UInt8]: [UInt8]] = [:]
    var verifySW: UInt16 = 0x9000
    private(set) var sent: [APDU] = []
    private var current: [UInt8]?

    func transmit(_ apdu: APDU) throws -> APDUResponse {
        sent.append(apdu)
        switch apdu.ins {
        case 0xA4 where apdu.p1 == 0x04:
            return APDUResponse(data: [], sw: 0x9000)
        case 0xA4:
            guard let f = files[apdu.data] else { return APDUResponse(data: [], sw: 0x6A82) }
            current = apdu.data
            return APDUResponse(data: [0x6F, 0x00, UInt8(f.count >> 8), UInt8(f.count & 0xFF), 0, 0, 0, 0], sw: 0x9000)
        case 0xB0:
            guard let c = current, let f = files[c] else { return APDUResponse(data: [], sw: 0x6985) }
            let off = Int(apdu.p1) << 8 | Int(apdu.p2)
            guard off < f.count else { return APDUResponse(data: [], sw: 0x6B00) }
            return APDUResponse(data: Array(f[off..<min(f.count, off + (apdu.le ?? 256))]), sw: 0x9000)
        case 0x20:
            return APDUResponse(data: [], sw: verifySW)
        default:
            return APDUResponse(data: [], sw: 0x6D00)
        }
    }
}

private func cardFile(forDER der: Data) -> [UInt8] {
    let src = [UInt8](der)
    var dst = [UInt8](repeating: 0, count: src.count + 1024)
    let n = src.withUnsafeBufferPointer { s in
        dst.withUnsafeMutableBufferPointer { out in
            compression_encode_buffer(out.baseAddress!, out.count, s.baseAddress!, src.count, nil, COMPRESSION_ZLIB)
        }
    }
    return [1, 2, 3, 4, 5, 6, 0x78, 0xDA] + dst[0..<n] + [0, 0, 0, 0]
}

private func meta(_ cls: UInt8, file: [UInt8], label: String, id: UInt8) -> [UInt8] {
    [cls] + file + [UInt8(label.utf8.count)] + Array(label.utf8) + [20] + [UInt8](repeating: id, count: 20)
}

final class PKCS15Tests: XCTestCase {
    func testSigningCertHasNonRepudiation() {
        XCTAssertTrue(PKCS15.isSigningCert(PKCS15Fixtures.certSignature))
    }

    func testAuthOnlyCertIsNotSigning() {
        XCTAssertFalse(PKCS15.isSigningCert(PKCS15Fixtures.certAuthOnly))
    }

    func testCertWithoutKeyUsageAndGarbageAreNotSigning() {
        XCTAssertFalse(PKCS15.isSigningCert(PKCS15Fixtures.certNoKeyUsage))
        XCTAssertFalse(PKCS15.isSigningCert(Data([1, 2, 3])))
    }

    private func makeCard() -> FileCard {
        let card = FileCard()
        // index: 2 entries, FIDs stored low byte first -> 0x7001, 0x7002
        card.files[[0x8F, 0xFF]] = [2, 0, 0x01, 0x70, 0x02, 0x70]
        card.files[[0x70, 0x01]] = meta(1, file: [0x71, 0x01], label: "Auth", id: 0xA1)
        card.files[[0x70, 0x02]] = meta(1, file: [0x71, 0x02], label: "Signature", id: 0xB2)
        card.files[[0x71, 0x01]] = cardFile(forDER: PKCS15Fixtures.certAuthOnly)
        card.files[[0x71, 0x02]] = cardFile(forDER: PKCS15Fixtures.certSignature)
        return card
    }

    func testListsCertificatesAndFlagsSigningOne() throws {
        let certs = try PKCS15.certificates(from: makeCard(), pin: Secret(bytes: Array("1234".utf8)))
        XCTAssertEqual(certs.count, 2)
        XCTAssertEqual(certs.map { $0.isSigning }, [false, true])
        XCTAssertEqual(certs[1].der, PKCS15Fixtures.certSignature)
        XCTAssertEqual(certs[1].alias, Alias(alias: String(repeating: "B2", count: 20), name: "Signature"))
    }

    func testSigningCertificatePicksNonRepudiationCert() throws {
        let (der, alias) = try PKCS15.signingCertificate(from: makeCard(), pin: Secret(bytes: Array("1234".utf8)))
        XCTAssertEqual(der, PKCS15Fixtures.certSignature)
        XCTAssertEqual(alias.name, "Signature")
    }

    func testWrongPINMapsToPinIncorrectAndSendsOneVerify() {
        let card = makeCard()
        card.verifySW = 0x63C2
        XCTAssertThrowsError(try PKCS15.certificates(from: card, pin: Secret(bytes: Array("1234".utf8)))) {
            XCTAssertEqual($0 as? CardError, .pinIncorrect)
        }
        XCTAssertEqual(card.sent.filter { $0.ins == 0x20 }.count, 1)
        XCTAssertEqual(card.sent.last?.ins, 0x20, "no card reads after a failed VERIFY")
    }

    func testBlockedPINMapsToPinLocked() {
        let card = makeCard()
        card.verifySW = 0x6983
        XCTAssertThrowsError(try PKCS15.certificates(from: card, pin: Secret(bytes: Array("1234".utf8)))) {
            XCTAssertEqual($0 as? CardError, .pinLocked)
        }
    }

    func testMalformedPINIsRejectedWithoutTouchingCard() {
        let card = makeCard()
        XCTAssertThrowsError(try PKCS15.certificates(from: card, pin: Secret(bytes: Array("12ab".utf8)))) {
            XCTAssertEqual($0 as? CardError, .pinIncorrect)
        }
        XCTAssertTrue(card.sent.isEmpty)
    }

    func testNoSigningCertThrowsGeneric() {
        let card = makeCard()
        card.files[[0x71, 0x02]] = cardFile(forDER: PKCS15Fixtures.certAuthOnly)
        XCTAssertThrowsError(try PKCS15.signingCertificate(from: card, pin: Secret(bytes: Array("1234".utf8)))) {
            XCTAssertEqual($0 as? CardError, .generic)
        }
    }

    func testServiceFilterKeepsOnlySigningCert() throws {
        let aliases = try PKCS15.signingAliases(from: makeCard(), pin: Secret(bytes: Array("1234".utf8)))
        XCTAssertEqual(aliases.map { $0.name }, ["Signature"])
    }

    func testMUPATRGate() {
        let known = Array(Data(base64Encoded: "O/mWAACAMf5FU0NFNyBHQ04zXg==")!)  // 3BF99600008031FE45534345372047434E335E
        XCTAssertEqual(known.first, 0x3B)
        XCTAssertTrue(PKCS15.isMUPATR(known))
        XCTAssertFalse(PKCS15.isMUPATR([0x3B, 0x8F, 0x80, 0x01]))
        XCTAssertFalse(PKCS15.isMUPATR([]))
    }
}
