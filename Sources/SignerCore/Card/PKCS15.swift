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

struct CardCertificate {
    let der: Data
    let alias: Alias
    let isSigning: Bool

    let privateKeyFID: [UInt8]?
}

enum PKCS15 {
    static let appletAID: [UInt8] = [0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35]

    static let mupATRPrefix: [UInt8] = [0x3B, 0xF9, 0x96, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45]

    static func isMUPATR(_ atr: [UInt8]) -> Bool {
        atr.starts(with: mupATRPrefix)
    }

    static func isSigningCert(_ der: Data) -> Bool {
        guard let bits = keyUsageByte(der) else { return false }
        return bits & 0x40 != 0
    }

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

    static func certificates(from transport: APDUTransport, pin: Secret) throws -> [CardCertificate] {
        do {

            var digits = pin.bytes
            defer { Secret.zeroize(&digits) }
            guard (4...8).contains(digits.count), digits.allSatisfy({ (0x30...0x39).contains($0) }) else {
                throw CardError.pinIncorrect
            }
            let reader = FileReader(transport: transport)
            try reader.selectApplet()
            var padded = digits + [UInt8](repeating: 0, count: 8 - digits.count)
            defer { Secret.zeroize(&padded) }
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

    static func signingAliases(from transport: APDUTransport, pin: Secret) throws -> [Alias] {
        try certificates(from: transport, pin: pin).filter { $0.isSigning }.map { $0.alias }
    }

    static func signingCertificate(from transport: APDUTransport, pin: Secret) throws -> (cert: Data, alias: Alias) {
        guard let c = try certificates(from: transport, pin: pin).first(where: { $0.isSigning }) else {
            throw CardError.generic
        }
        return (c.der, c.alias)
    }

    static func certificateDER(from transport: APDUTransport, pin: Secret, alias: Alias) throws -> Data {
        guard let c = try certificates(from: transport, pin: pin).first(where: { $0.alias.alias == alias.alias }) else {
            throw CardError.generic
        }
        return c.der
    }

    static let sha256DigestInfoPrefix: [UInt8] = [
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ]

    static func withSigningKey<T>(from transport: APDUTransport, pin: Secret, alias: Alias,
                                  _ body: (_ certDER: Data, _ sign: (Data) throws -> Data) throws -> T) throws -> T {
        guard let c = try certificates(from: transport, pin: pin).first(where: { $0.alias.alias == alias.alias }),
              c.isSigning, let keyFID = c.privateKeyFID, keyFID.count == 2 else {
            throw CardError.generic
        }
        let sign: (Data) throws -> Data = { sha256Digest in
            guard sha256Digest.count == 32 else { throw CardError.generic }
            let digestInfo = sha256DigestInfoPrefix + [UInt8](sha256Digest)
            do {
                let mse = try transport.transmit(APDU(ins: 0x22, p1: 0x41, p2: 0xB6, data: [0x80, 0x01, 0x02, 0x84, 0x02] + keyFID))
                guard mse.isOK else { throw CardError.generic }
                let pso = try transport.transmit(APDU(ins: 0x2A, p1: 0x9E, p2: 0x00, data: digestInfo, le: 256))
                guard pso.isOK, !pso.data.isEmpty else { throw CardError.generic }
                return Data(pso.data)
            } catch let e as CardError {
                throw e
            } catch {
                throw CardError.generic
            }
        }
        return try body(c.der, sign)
    }

    static func sign(from transport: APDUTransport, pin: Secret, alias: Alias, sha256Digest: Data) throws -> Data {
        guard sha256Digest.count == 32 else { throw CardError.generic }
        return try withSigningKey(from: transport, pin: pin, alias: alias) { _, sign in try sign(sha256Digest) }
    }

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

        private func privateKeyFID(inPublicKeyFile f: [UInt8]) -> [UInt8]? {
            guard f.count >= 7, f[0] == 0x00, f[1] == 0x05 else { return nil }
            return [f[3], f[4]]
        }

        func discoverCertificates() throws -> [CardCertificate] {
            let index = try readFile([0x8F, 0xFF])
            guard index.count >= 2 else { throw APDUError.malformed("index too short") }
            let count = Int(index[0]) | Int(index[1]) << 8
            guard index.count >= 2 + count * 2 else { throw APDUError.malformed("index truncated") }
            var certs: [(id: [UInt8], label: String, der: Data)] = []
            var keyFIDs: [[UInt8]: [UInt8]] = [:]
            for i in 0..<count {
                let fid = [index[3 + i * 2], index[2 + i * 2]]
                do {
                    let m = try readFile(fid)
                    guard m.count >= 4, m[0] == 1 || m[0] == 2 else { continue }
                    let file = Array(m[1..<3])
                    let labelLen = Int(m[3])
                    guard m.count >= 5 + labelLen + 20, m[4 + labelLen] == 20 else { continue }
                    let label = String(bytes: m[4..<4 + labelLen], encoding: .utf8) ?? ""
                    let id = Array(m[5 + labelLen..<5 + labelLen + 20])
                    if m[0] == 1 {
                        certs.append((id, label, try PKCS15.decodeCertificateFile(try readFile(file))))
                    } else if let fid = privateKeyFID(inPublicKeyFile: try readFile(file)) {
                        keyFIDs[id] = fid
                    }
                } catch let e as APDUError {
                    if case .transport = e { throw e }
                    continue
                }
            }
            let out = certs.map { c in

                let holder = (try? CertificateInfo(der: c.der).holderName) ?? ""
                let name = !holder.isEmpty ? holder : (c.label.isEmpty ? "Certificate" : c.label)
                return CardCertificate(
                    der: c.der,
                    alias: Alias(alias: c.id.map { String(format: "%02X", $0) }.joined(), name: name),
                    isSigning: PKCS15.isSigningCert(c.der),
                    privateKeyFID: keyFIDs[c.id])
            }
            return out
        }
    }
}
