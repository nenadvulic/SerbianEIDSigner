import Foundation
import CryptoKit
import CLibXML2

public enum XMLDSigError: Error {
    case parseFailed
    case canonicalizationFailed
    case signatureElementMissing
}

public struct XMLDSigBuilder {
    static let dsigNS = "http://www.w3.org/2000/09/xmldsig#"
    static let c14nURI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    static let sigMethodURI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    static let digestMethodURI = "http://www.w3.org/2001/04/xmlenc#sha256"
    static let envelopedURI = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

    public init() {}

    public func build(documentXML: String, certDER: Data, issuer: String, serial: Data,
                      subject: String = "", sign: (Data) throws -> Data) throws -> String {
        let doc = try Self.parse(documentXML)
        defer { xmlFreeDoc(doc) }
        guard let root = xmlDocGetRootElement(doc) else { throw XMLDSigError.parseFailed }

        let docDigest = Data(SHA256.hash(data: try Self.c14n(doc: doc, visibleUnder: nil)))

        let sig = Self.element("Signature", parent: root, ns: nil, declareNS: Self.dsigNS)
        let ns = sig.pointee.nsDef
        let signedInfo = Self.element("SignedInfo", parent: sig, ns: ns)
        let cm = Self.element("CanonicalizationMethod", parent: signedInfo, ns: ns)
        xmlSetProp(cm, "Algorithm", Self.c14nURI)
        let sm = Self.element("SignatureMethod", parent: signedInfo, ns: ns)
        xmlSetProp(sm, "Algorithm", Self.sigMethodURI)
        let ref = Self.element("Reference", parent: signedInfo, ns: ns)
        xmlSetProp(ref, "URI", "")
        let transforms = Self.element("Transforms", parent: ref, ns: ns)
        let tr = Self.element("Transform", parent: transforms, ns: ns)
        xmlSetProp(tr, "Algorithm", Self.envelopedURI)
        let dm = Self.element("DigestMethod", parent: ref, ns: ns)
        xmlSetProp(dm, "Algorithm", Self.digestMethodURI)
        _ = Self.element("DigestValue", parent: ref, ns: ns, text: docDigest.base64EncodedString())

        let siDigest = Data(SHA256.hash(data: try Self.c14n(doc: doc, visibleUnder: signedInfo)))
        let sigBytes = try sign(siDigest)
        _ = Self.element("SignatureValue", parent: sig, ns: ns, text: sigBytes.base64EncodedString())

        let keyInfo = Self.element("KeyInfo", parent: sig, ns: ns)
        let x509 = Self.element("X509Data", parent: keyInfo, ns: ns)
        _ = Self.element("X509Certificate", parent: x509, ns: ns, text: certDER.base64EncodedString())
        let isr = Self.element("X509IssuerSerial", parent: x509, ns: ns)
        _ = Self.element("X509IssuerName", parent: isr, ns: ns, text: issuer)
        _ = Self.element("X509SerialNumber", parent: isr, ns: ns, text: Self.decimal(serial))
        // ePorezi reads the user from X509SubjectName and rejects the login without it.
        if !subject.isEmpty { _ = Self.element("X509SubjectName", parent: x509, ns: ns, text: subject) }

        var buf: UnsafeMutablePointer<xmlChar>?
        var size: Int32 = 0
        xmlDocDumpMemoryEnc(doc, &buf, &size, "UTF-8")
        guard let b = buf else { throw XMLDSigError.parseFailed }
        defer { xmlFree(b) }
        return String(decoding: UnsafeBufferPointer(start: b, count: Int(size)), as: UTF8.self)
    }

    static func canonicalize(xml: String) throws -> Data {
        let doc = try parse(xml)
        defer { xmlFreeDoc(doc) }
        return try c14n(doc: doc, visibleUnder: nil)
    }

    static func canonicalizeSignedInfo(inSignedXML xml: String) throws -> Data {
        let doc = try parse(xml)
        defer { xmlFreeDoc(doc) }
        guard let root = xmlDocGetRootElement(doc) else { throw XMLDSigError.parseFailed }
        var found: xmlNodePtr?
        var n = root.pointee.children
        while let c = n {
            if c.pointee.type == XML_ELEMENT_NODE, String(cString: c.pointee.name) == "Signature" {
                var m = c.pointee.children
                while let k = m {
                    if k.pointee.type == XML_ELEMENT_NODE, String(cString: k.pointee.name) == "SignedInfo" { found = k; break }
                    m = k.pointee.next
                }
            }
            n = c.pointee.next
        }
        guard let si = found else { throw XMLDSigError.signatureElementMissing }
        return try c14n(doc: doc, visibleUnder: si)
    }

    private static func c14n(doc: xmlDocPtr, visibleUnder subtree: xmlNodePtr?) throws -> Data {
        guard let out = xmlAllocOutputBuffer(nil) else { throw XMLDSigError.canonicalizationFailed }
        var root = subtree
        let rc: Int32 = withUnsafeMutablePointer(to: &root) { p in
            let cb: xmlC14NIsVisibleCallback? = subtree == nil ? nil : { ud, node, parent in
                guard let target = ud!.assumingMemoryBound(to: xmlNodePtr?.self).pointee else { return 1 }
                var cur: xmlNodePtr? = node
                if node?.pointee.type == XML_NAMESPACE_DECL { cur = parent }
                while let c = cur {
                    if c == target { return 1 }
                    cur = c.pointee.parent
                }
                return 0
            }
            return xmlC14NExecute(doc, cb, p, Int32(XML_C14N_1_0.rawValue), nil, 0, out)
        }
        guard rc >= 0 else { xmlOutputBufferClose(out); throw XMLDSigError.canonicalizationFailed }
        let len = xmlOutputBufferGetSize(out)
        let data: Data
        if let content = xmlOutputBufferGetContent(out), len > 0 {
            data = Data(bytes: content, count: Int(len))
        } else {
            data = Data()
        }
        xmlOutputBufferClose(out)
        return data
    }

    private static func parse(_ xml: String) throws -> xmlDocPtr {
        let bytes = Array(xml.utf8)
        guard !bytes.isEmpty else { throw XMLDSigError.parseFailed }
        let opts = Int32(XML_PARSE_NONET.rawValue)
        let doc: xmlDocPtr? = bytes.withUnsafeBufferPointer { bp in
            bp.baseAddress!.withMemoryRebound(to: CChar.self, capacity: bytes.count) {
                xmlReadMemory($0, Int32(bytes.count), nil, "UTF-8", opts)
            }
        }
        guard let d = doc else { throw XMLDSigError.parseFailed }
        return d
    }

    private static func element(_ name: String, parent: xmlNodePtr, ns: UnsafeMutablePointer<xmlNs>?,
                                declareNS: String? = nil, text: String? = nil) -> xmlNodePtr {
        let node = xmlNewDocNode(parent.pointee.doc, ns, name, nil)!
        if let uri = declareNS {
            let newNS = xmlNewNs(node, uri, nil)
            node.pointee.ns = newNS
        }
        if let t = text { xmlAddChild(node, xmlNewDocText(parent.pointee.doc, t)) }
        xmlAddChild(parent, node)
        return node
    }

    static func decimal(_ bytes: Data) -> String {
        var num = Array(bytes)
        while num.first == 0 { num.removeFirst() }
        if num.isEmpty { return "0" }
        var digits: [UInt8] = []
        while !num.isEmpty {
            var rem = 0
            var next: [UInt8] = []
            for b in num {
                let cur = rem * 256 + Int(b)
                let q = cur / 10
                rem = cur % 10
                if !next.isEmpty || q != 0 { next.append(UInt8(q)) }
            }
            digits.append(UInt8(rem))
            num = next
        }
        return String(digits.reversed().map { Character(UnicodeScalar($0 + 48)) })
    }
}
