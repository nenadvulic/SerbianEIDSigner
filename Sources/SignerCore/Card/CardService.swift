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
    /// One signing operation in ONE card session (one VERIFY, no retry): resolves the signing certificate for
    /// `alias`, then calls `build` with its DER and a `sign` closure (SHA-256 digest of the canonical SignedInfo
    /// -> RSA signature bytes). Returns whatever `build` returns (the signed XML).
    func withSigningKey(providerId: Int, terminalId: Int, alias: Alias, pin: Secret,
                        build: (_ certDER: Data, _ sign: (Data) throws -> Data) throws -> String) throws -> String
}
