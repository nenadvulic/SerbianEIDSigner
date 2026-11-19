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

    func withSigningKey(providerId: Int, terminalId: Int, alias: Alias, pin: Secret,
                        build: (_ certDER: Data, _ sign: (Data) throws -> Data) throws -> String) throws -> String
}
