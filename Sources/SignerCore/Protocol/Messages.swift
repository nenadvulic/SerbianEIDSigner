import Foundation

public enum Operation: String, Codable, Sendable {
    case onOpenEvent = "ON_OPEN_EVENT"
    case getInfo = "GET_INFO"
    case getProviders = "GET_PROVIDERS"
    case getTerminals = "GET_TERMINALS"
    case getCertificates = "GET_CERTIFICATES"
    case getSignedXml = "GET_SIGNED_XML"
}

/// Wire status code; encodes as a bare JSON number. 0 = success.
public struct Status: Codable, Equatable, Sendable {
    public let code: Int
    public init(_ code: Int) { self.code = code }
    public static let ok = Status(0)

    public init(from decoder: Decoder) throws {
        code = try decoder.singleValueContainer().decode(Int.self)
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(code)
    }
}

public struct Envelope<Payload: Codable>: Codable {
    public let operation: Operation
    public let status: Status
    public let payload: Payload
    public init(operation: Operation, status: Status, payload: Payload) {
        self.operation = operation
        self.status = status
        self.payload = payload
    }
}

/// Typed request input, decoded per operation. PIN-bearing inputs go
/// Decoder -> Secret directly, with no dynamic/Encodable intermediary.
public enum RequestInput {
    case none
    case getInfo(GetInfoInput)
    case getTerminals(GetTerminalsInput)
    case getCertificates(GetCertificatesInput)
    case getSignedXml(GetSignedXmlInput)
}

public struct Request: Decodable {
    public let operation: Operation
    public let input: RequestInput

    private enum CodingKeys: String, CodingKey { case operation, input }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        operation = try c.decode(Operation.self, forKey: .operation)
        switch operation {
        case .getInfo: input = .getInfo(try c.decode(GetInfoInput.self, forKey: .input))
        case .getTerminals: input = .getTerminals(try c.decode(GetTerminalsInput.self, forKey: .input))
        case .getCertificates: input = .getCertificates(try c.decode(GetCertificatesInput.self, forKey: .input))
        case .getSignedXml: input = .getSignedXml(try c.decode(GetSignedXmlInput.self, forKey: .input))
        case .onOpenEvent, .getProviders: input = .none
        }
    }
}

/// Holds PIN bytes. Deliberately not Encodable; redacted when printed; zeroized on deinit.
public final class Secret: Decodable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private var storage: [UInt8]
    public var bytes: [UInt8] { storage }

    public init(bytes: [UInt8]) { storage = bytes }

    public required init(from decoder: Decoder) throws {
        let s = try decoder.singleValueContainer().decode(String.self)
        storage = Array(s.utf8)
    }

    public var description: String { "<redacted>" }
    public var debugDescription: String { "<redacted>" }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }

    /// Zeroes in place via memset_s, which the optimizer is not allowed to elide.
    static func zeroize(_ a: inout [UInt8]) {
        a.withUnsafeMutableBytes { buf in
            if let base = buf.baseAddress, buf.count > 0 { _ = memset_s(base, buf.count, 0, buf.count) }
        }
    }

    deinit { Secret.zeroize(&storage) }
}

public struct Alias: Codable, Equatable, Sendable {
    public let alias: String
    public let name: String
    public init(alias: String, name: String) { self.alias = alias; self.name = name }
}

public struct GetInfoInput: Decodable {
    public let sbSession: String
    public let host: String
    public let language: String
}

public struct GetTerminalsInput: Decodable {
    public let providerId: Int
}

public struct GetCertificatesInput: Decodable {
    public let pin: Secret
    public let terminalId: Int
}

public struct GetSignedXmlInput: Decodable {
    public let certificate: Alias
    public let pin: Secret
    public let xml: String
}
