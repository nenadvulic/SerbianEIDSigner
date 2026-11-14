import Foundation

public struct Provider: Codable, Equatable, Sendable {
    public let id: Int
    public let name: String
    public init(id: Int, name: String) { self.id = id; self.name = name }
}

public struct Terminal: Codable, Equatable, Sendable {
    public let id: Int
    public let name: String
    public init(id: Int, name: String) { self.id = id; self.name = name }
}

/// Card failures. Never retried by the dispatcher (a retry with a wrong PIN burns attempts).
public enum CardError: Error, Equatable {
    case pinIncorrect
    case pinLocked
    case middleware
    case generic
}

public protocol CardService {
    func providers() -> [Provider]
    func terminals(providerId: Int) throws -> [Terminal]
    func certificates(providerId: Int, terminalId: Int, pin: Secret) throws -> [Alias]
    /// DER of the certificate with this alias (needed for KeyInfo and the issuer/serial of the signature).
    func signingCertificate(providerId: Int, terminalId: Int, alias: Alias, pin: Secret) throws -> Data
    func sign(providerId: Int, terminalId: Int, alias: Alias, pin: Secret, canonicalSignedInfoSHA256: Data) throws -> Data
}
