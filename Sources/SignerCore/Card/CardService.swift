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

public protocol CardService {
    func providers() -> [Provider]
    func terminals(providerId: Int) -> [Terminal]
    func certificates(providerId: Int, terminalId: Int, pin: Secret) throws -> [Alias]
    func sign(providerId: Int, terminalId: Int, alias: Alias, pin: Secret, canonicalSignedInfoSHA256: Data) throws -> Data
}
