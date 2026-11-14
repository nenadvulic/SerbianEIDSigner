// PKCS#15 / MUP eID card file access over an abstract APDU transport.
// APDU encoding, SELECT/READ BINARY strategy, directory/meta/certificate file formats, VERIFY and the
// keyUsage walk are adapted from SerbianEIDToken (MIT, (c) 2026 Nenad VULIC).
import Foundation
import Compression

struct APDU: Equatable {
    var cla: UInt8 = 0x00
    var ins: UInt8
    var p1: UInt8
    var p2: UInt8
    var data: [UInt8] = []
    var le: Int?
}

struct APDUResponse {
    var data: [UInt8]
    var sw: UInt16
    var isOK: Bool { sw == 0x9000 }
}

protocol APDUTransport {
    func transmit(_ apdu: APDU) throws -> APDUResponse
}

enum APDUError: Error, Equatable {
    case status(UInt16)
    case malformed(String)
    case unsupportedCard
    case transport(String)
}

/// A certificate found on the card.
struct CardCertificate {
    let der: Data
    let alias: Alias
    let isSigning: Bool
}

enum PKCS15 {
    static let appletAID: [UInt8] = [0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35]

    // MARK: keyUsage

    /// True iff the certificate's keyUsage asserts nonRepudiation (the qualified signing certificate).
    static func isSigningCert(_ der: Data) -> Bool {
        guard let bits = keyUsageByte(der) else { return false }
        return bits & 0x40 != 0
    }

    /// First byte of the keyUsage BIT STRING (bit 0 = 0x80), found by walking the extension.
    private static func keyUsageByte(_ der: Data) -> UInt8? {
        let b = [UInt8](der)
        let oid: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x0F]
        guard b.count > oid.count else { return nil }
        var i = 0
        while i + oid.count <= b.count {
            if Array(b[i..<i + oid.count]) == oid { break }
            i += 1
        }
        guard i + oid.count <= b.count else { return nil }
        var pos = i + oid.count
        func tlv(_ tag: UInt8) -> (start: Int, len: Int)? {
            guard pos + 2 <= b.count, b[pos] == tag else { return nil }
            var len = Int(b[pos + 1])
            var hdr = 2
            if len & 0x80 != 0 {
                let n = len & 0x7F
                guard n >= 1, n <= 2, pos + 2 + n <= b.count else { return nil }
                len = 0
                for k in 0..<n { len = len << 8 | Int(b[pos + 2 + k]) }
                hdr += n
            }
            guard pos + hdr + len <= b.count else { return nil }
            return (pos + hdr, len)
        }
        if let critical = tlv(0x01) { pos = critical.start + critical.len }
        guard let octets = tlv(0x04) else { return nil }
        pos = octets.start
        guard let bitString = tlv(0x03), bitString.len >= 2 else { return nil }
        return b[bitString.start + 1]
    }

    // MARK: card access

    /// Selects the applet, verifies the PIN (exactly one VERIFY, never retried), then lists all certificates.
    static func certificates(from transport: APDUTransport, pin: Secret) throws -> [CardCertificate] {
        do {
            let digits = pin.bytes
            guard (4...8).contains(digits.count), digits.allSatisfy({ (0x30...0x39).contains($0) }) else {
                throw CardError.pinIncorrect
            }
            let reader = FileReader(transport: transport)
            try reader.selectApplet()
            var padded = digits + [UInt8](repeating: 0, count: 8 - digits.count)
            defer { for i in padded.indices { padded[i] = 0 } }
            let verify = try transport.transmit(APDU(ins: 0x20, p1: 0x00, p2: 0x80, data: padded))
            switch verify.sw {
            case 0x9000: break
            case 0x6983, 0x63C0: throw CardError.pinLocked
            default: throw CardError.pinIncorrect
            }
            return try reader.discoverCertificates()
        } catch let e as CardError {
            throw e
        } catch {
            throw CardError.generic
        }
    }

    static func signingCertificate(from transport: APDUTransport, pin: Secret) throws -> (cert: Data, alias: Alias) {
        guard let c = try certificates(from: transport, pin: pin).first(where: { $0.isSigning }) else {
            throw CardError.generic
        }
        return (c.der, c.alias)
    }

    /// Certificate file: 6 bytes header, zlib stream (2-byte header, raw deflate, Adler-32).
    static func decodeCertificateFile(_ f: [UInt8]) throws -> Data {
        guard f.count > 6 + 2 + 4 else { throw APDUError.malformed("certificate file too short") }
        let deflate = Array(f[8..<(f.count - 4)])
        var capacity = max(deflate.count * 8, 4096)
        while capacity <= 16 * 1024 * 1024 {
            var dst = [UInt8](repeating: 0, count: capacity)
            let n = deflate.withUnsafeBufferPointer { src in
                dst.withUnsafeMutableBufferPointer { out in
                    compression_decode_buffer(out.baseAddress!, capacity, src.baseAddress!, deflate.count, nil, COMPRESSION_ZLIB)
                }
            }
            if n == 0 { throw APDUError.malformed("certificate decompression failed") }
            if n < capacity { return Data(dst[0..<n]) }
            capacity *= 2
        }
        throw APDUError.malformed("certificate too large")
    }

    final class FileReader {
        let transport: APDUTransport
        private var selectStrategy: Int?
        init(transport: APDUTransport) { self.transport = transport }

        func selectApplet() throws {
            let r = try transport.transmit(APDU(ins: 0xA4, p1: 0x04, p2: 0x00, data: PKCS15.appletAID, le: 255))
            guard r.isOK else { throw APDUError.unsupportedCard }
        }

        /// SELECT strategies in order: Le=FF, no Le, no Le with P2=04 (FCI). The first that works is remembered.
        private func select(_ fid: [UInt8]) throws -> APDUResponse {
            var last = APDUResponse(data: [], sw: 0x6F00)
            for s in selectStrategy.map({ [$0] }) ?? [0, 1, 2] {
                let apdu: APDU
                switch s {
                case 0: apdu = APDU(ins: 0xA4, p1: 0, p2: 0, data: fid, le: 0xFF)
                case 1: apdu = APDU(ins: 0xA4, p1: 0, p2: 0, data: fid)
                default: apdu = APDU(ins: 0xA4, p1: 0, p2: 0x04, data: fid)
                }
                let r = try transport.transmit(apdu)
                if r.isOK { selectStrategy = s; return r }
                last = r
                if r.sw != 0x6F00 { break }
            }
            throw APDUError.status(last.sw)
        }

        func readFile(_ fid: [UInt8]) throws -> [UInt8] {
            let fci = try select(fid).data
            var size: Int?
            if fci.count >= 6 { size = Int(fci[2]) << 8 | Int(fci[3]) }
            var out: [UInt8] = []
            while size == nil || out.count < size! {
                let want = min(size.map { $0 - out.count } ?? 255, 255)
                let r = try transport.transmit(APDU(ins: 0xB0, p1: UInt8((out.count >> 8) & 0xFF), p2: UInt8(out.count & 0xFF), le: want))
                if !r.isOK {
                    if size == nil && !out.isEmpty { break }
                    throw APDUError.status(r.sw)
                }
                if r.data.isEmpty { break }
                out.append(contentsOf: r.data)
            }
            return out
        }

        /// Directory file 8FFF: entry count (LE16) then 2-byte FIDs stored low byte first. Each entry is a meta
        /// file: class(1) fileName(2) labelLen(1) label idLen(1)=20 id. Class 1 = certificate.
        func discoverCertificates() throws -> [CardCertificate] {
            let index = try readFile([0x8F, 0xFF])
            guard index.count >= 2 else { throw APDUError.malformed("index too short") }
            let count = Int(index[0]) | Int(index[1]) << 8
            guard index.count >= 2 + count * 2 else { throw APDUError.malformed("index truncated") }
            var out: [CardCertificate] = []
            for i in 0..<count {
                let fid = [index[3 + i * 2], index[2 + i * 2]]
                do {
                    let m = try readFile(fid)
                    guard m.count >= 4, m[0] == 1 else { continue }  // certificates only
                    let file = Array(m[1..<3])
                    let labelLen = Int(m[3])
                    guard m.count >= 5 + labelLen + 20, m[4 + labelLen] == 20 else { continue }
                    let label = String(bytes: m[4..<4 + labelLen], encoding: .utf8) ?? ""
                    let id = m[5 + labelLen..<5 + labelLen + 20]
                    let der = try PKCS15.decodeCertificateFile(try readFile(file))
                    out.append(CardCertificate(
                        der: der,
                        alias: Alias(alias: id.map { String(format: "%02X", $0) }.joined(),
                                     name: label.isEmpty ? "Certificate" : label),
                        isSigning: PKCS15.isSigningCert(der)))
                } catch let e as APDUError {
                    if case .transport = e { throw e }
                    continue  // corrupt or unreadable object: keep the others
                }
            }
            return out
        }
    }
}
