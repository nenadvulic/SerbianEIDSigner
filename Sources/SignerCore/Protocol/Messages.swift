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

/// Minimal dynamic JSON value.
public enum JSONValue: Codable, Equatable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .number(let n): try c.encode(n)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}

public struct Request: Decodable {
    public let operation: Operation
    public let input: JSONValue?

    /// Decodes the dynamic input into a typed struct. The PIN, if any, is
    /// built directly into a `Secret` (never an Encodable value).
    public func decodeInput<T: Decodable>(_ type: T.Type) throws -> T {
        guard let input else {
            throw DecodingError.valueNotFound(T.self, .init(codingPath: [], debugDescription: "missing input"))
        }
        let data = try JSONEncoder().encode(input)
        return try JSONDecoder().decode(T.self, from: data)
    }
}

/// Holds PIN bytes. Deliberately not Encodable; redacted when printed; zeroized on deinit.
public final class Secret: Decodable, CustomStringConvertible, CustomDebugStringConvertible {
    private var storage: [UInt8]
    public var bytes: [UInt8] { storage }

    public init(bytes: [UInt8]) { storage = bytes }

    public required init(from decoder: Decoder) throws {
        let s = try decoder.singleValueContainer().decode(String.self)
        storage = Array(s.utf8)
    }

    public var description: String { "<redacted>" }
    public var debugDescription: String { "<redacted>" }

    deinit {
        storage.withUnsafeMutableBytes { buf in
            for i in 0..<buf.count { buf[i] = 0 }
        }
    }
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
