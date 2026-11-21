import XCTest
import Compression
@testable import SignerCore

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
        case 0x22:
            return APDUResponse(data: [], sw: 0x9000)
        case 0x2A:
            return APDUResponse(data: [UInt8](repeating: 0xCD, count: 256), sw: 0x9000)
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

private func sign(_ card: FileCard, alias: Alias, digest: Data, pin: String = "1234") throws -> Data {
    try PKCS15.withSigningKey(from: card, pin: Secret(bytes: Array(pin.utf8)), alias: alias) { _, sign in try sign(digest) }
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
        XCTAssertEqual(certs[1].alias, Alias(alias: String(repeating: "B2", count: 20), name: "Test Signature"))
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

    func testServiceFilterKeepsOnlySigningCert() throws {
        let aliases = try PKCS15.signingAliases(from: makeCard(), pin: Secret(bytes: Array("1234".utf8)))
        XCTAssertEqual(aliases.map { $0.name }, ["Test Signature"])
    }

    func testMUPATRGate() {
        let known = Array(Data(base64Encoded: "O/mWAACAMf5FU0NFNyBHQ04zXg==")!)
        XCTAssertEqual(known.first, 0x3B)
        XCTAssertTrue(PKCS15.isMUPATR(known))
        XCTAssertFalse(PKCS15.isMUPATR([0x3B, 0x8F, 0x80, 0x01]))
        XCTAssertFalse(PKCS15.isMUPATR([]))
    }

    private func makeSigningCard() -> FileCard {
        let card = makeCard()
        card.files[[0x8F, 0xFF]] = [3, 0, 0x01, 0x70, 0x02, 0x70, 0x03, 0x70]
        card.files[[0x70, 0x03]] = meta(2, file: [0x72, 0x03], label: "SigKey", id: 0xB2)
        // Public key file; bytes 3-4 hold the private key FID (60 05).
        card.files[[0x72, 0x03]] = [0x00, 0x05, 0x00, 0x60, 0x05, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x03, 0x01, 0x00, 0x01]
        return card
    }

    func testSignSendsVerifyThenMSEThenPSOWithSHA256DigestInfo() throws {
        let card = makeSigningCard()
        let digest = Data((0..<32).map { UInt8($0) })
        let alias = Alias(alias: String(repeating: "B2", count: 20), name: "Signature")
        let sig = try sign(card, alias: alias, digest: digest)
        XCTAssertEqual(sig, Data(repeating: 0xCD, count: 256))
        XCTAssertEqual(card.sent.filter { $0.ins == 0x20 }.count, 1)
        let mse = try XCTUnwrap(card.sent.first { $0.ins == 0x22 })
        XCTAssertEqual(mse.data, [0x80, 0x01, 0x02, 0x84, 0x02, 0x60, 0x05])
        let pso = try XCTUnwrap(card.sent.first { $0.ins == 0x2A })
        let prefix: [UInt8] = [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
        XCTAssertEqual([pso.p1, pso.p2], [0x9E, 0x00])
        XCTAssertEqual(pso.data, prefix + [UInt8](digest))
        let order = card.sent.map { $0.ins }.filter { [0x20, 0x22, 0x2A].contains($0) }
        XCTAssertEqual(order, [0x20, 0x22, 0x2A])
    }

    func testSignRejectsBadDigestUnknownAliasAndAuthCert() {
        let good = Alias(alias: String(repeating: "B2", count: 20), name: "Signature")
        XCTAssertThrowsError(try sign(makeSigningCard(), alias: good, digest: Data([1, 2])))
        let unknown = Alias(alias: "00", name: "x")
        XCTAssertThrowsError(try sign(makeSigningCard(), alias: unknown, digest: Data(count: 32))) {
            XCTAssertEqual($0 as? CardError, .generic)
        }
        let auth = Alias(alias: String(repeating: "A1", count: 20), name: "Auth")
        XCTAssertThrowsError(try sign(makeSigningCard(), alias: auth, digest: Data(count: 32))) {
            XCTAssertEqual($0 as? CardError, .generic)
        }
    }

    func testSigningKeySessionVerifiesOnceAndEnumeratesCertsOnce() throws {
        let card = makeSigningCard()
        let alias = Alias(alias: String(repeating: "B2", count: 20), name: "Signature")
        let digest = Data(count: 32)
        let der = try PKCS15.withSigningKey(from: card, pin: Secret(bytes: Array("1234".utf8)), alias: alias) { der, sign in
            _ = try sign(digest)
            _ = try sign(digest)
            return der
        }
        XCTAssertEqual(der, PKCS15Fixtures.certSignature)
        XCTAssertEqual(card.sent.filter { $0.ins == 0x20 }.count, 1)
        XCTAssertEqual(card.sent.filter { $0.ins == 0xA4 && $0.p1 == 0x04 }.count, 1, "applet selected once")
    }

    func testSignWrongPINNeverReachesSigning() {
        let card = makeSigningCard()
        card.verifySW = 0x63C2
        let alias = Alias(alias: String(repeating: "B2", count: 20), name: "Signature")
        XCTAssertThrowsError(try sign(card, alias: alias, digest: Data(count: 32))) {
            XCTAssertEqual($0 as? CardError, .pinIncorrect)
        }
        XCTAssertFalse(card.sent.contains { $0.ins == 0x22 || $0.ins == 0x2A })
    }
}
