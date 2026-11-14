import Foundation

/// Issuer name (RFC 2253 string) and serial number bytes of an X.509 certificate, read straight from the DER.
struct CertificateInfo {
    let issuer: String
    let serial: Data

    enum ParseError: Error { case malformed }

    private struct Reader {
        let b: [UInt8]
        var pos: Int
        let end: Int

        mutating func next() throws -> (tag: UInt8, content: Range<Int>) {
            guard pos + 2 <= end else { throw ParseError.malformed }
            let tag = b[pos]
            var len = Int(b[pos + 1])
            var p = pos + 2
            if len & 0x80 != 0 {
                let n = len & 0x7F
                guard n >= 1, n <= 3, p + n <= end else { throw ParseError.malformed }
                len = 0
                for k in 0..<n { len = len << 8 | Int(b[p + k]) }
                p += n
            }
            guard p + len <= end else { throw ParseError.malformed }
            pos = p + len
            return (tag, p..<p + len)
        }
    }

    private static let attributeNames: [[UInt8]: String] = [
        [0x55, 4, 3]: "CN", [0x55, 4, 7]: "L", [0x55, 4, 8]: "ST", [0x55, 4, 10]: "O",
        [0x55, 4, 11]: "OU", [0x55, 4, 6]: "C", [0x55, 4, 9]: "STREET",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19]: "DC",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01]: "UID",
    ]

    init(der: Data) throws {
        let b = [UInt8](der)
        var top = Reader(b: b, pos: 0, end: b.count)
        let cert = try top.next()
        guard cert.tag == 0x30 else { throw ParseError.malformed }
        var c = Reader(b: b, pos: cert.content.lowerBound, end: cert.content.upperBound)
        let tbsTLV = try c.next()
        guard tbsTLV.tag == 0x30 else { throw ParseError.malformed }
        var t = Reader(b: b, pos: tbsTLV.content.lowerBound, end: tbsTLV.content.upperBound)
        var f = try t.next()
        if f.tag == 0xA0 { f = try t.next() }  // optional [0] version
        guard f.tag == 0x02, !f.content.isEmpty else { throw ParseError.malformed }
        serial = Data(b[f.content])
        _ = try t.next()  // signature algorithm
        let name = try t.next()
        guard name.tag == 0x30 else { throw ParseError.malformed }
        issuer = try Self.rfc2253(b, name.content)
    }

    private static func rfc2253(_ b: [UInt8], _ range: Range<Int>) throws -> String {
        var rdns: [String] = []
        var r = Reader(b: b, pos: range.lowerBound, end: range.upperBound)
        while r.pos < r.end {
            let set = try r.next()
            guard set.tag == 0x31 else { throw ParseError.malformed }
            var s = Reader(b: b, pos: set.content.lowerBound, end: set.content.upperBound)
            var parts: [String] = []
            while s.pos < s.end {
                let atv = try s.next()
                guard atv.tag == 0x30 else { throw ParseError.malformed }
                var a = Reader(b: b, pos: atv.content.lowerBound, end: atv.content.upperBound)
                let oid = try a.next()
                let val = try a.next()
                guard oid.tag == 0x06 else { throw ParseError.malformed }
                let oidBytes = Array(b[oid.content])
                let key = attributeNames[oidBytes] ?? dotted(oidBytes)
                let raw = Array(b[val.content])
                let text = val.tag == 0x1E
                    ? String(bytes: raw, encoding: .utf16BigEndian) ?? ""
                    : String(decoding: raw, as: UTF8.self)
                parts.append("\(key)=\(escape(text))")
            }
            rdns.append(parts.joined(separator: "+"))
        }
        return rdns.reversed().joined(separator: ",")
    }

    private static func escape(_ s: String) -> String {
        var out = ""
        let chars = Array(s)
        for (i, ch) in chars.enumerated() {
            if ",+\"\\<>;".contains(ch) || (i == 0 && (ch == "#" || ch == " ")) || (i == chars.count - 1 && ch == " ") {
                out.append("\\")
            }
            out.append(ch)
        }
        return out
    }

    private static func dotted(_ o: [UInt8]) -> String {
        guard let first = o.first else { return "" }
        var parts = [String(Int(first) / 40), String(Int(first) % 40)]
        var v = 0
        for byte in o.dropFirst() {
            v = v << 7 | Int(byte & 0x7F)
            if byte & 0x80 == 0 { parts.append(String(v)); v = 0 }
        }
        return parts.joined(separator: ".")
    }
}
