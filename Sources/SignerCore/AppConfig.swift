import Foundation

public struct AppConfig: Equatable, Sendable {
    public var ports: [Int]
    public var originAllowlist: [String]

    public init(ports: [Int], originAllowlist: [String]) {
        self.ports = ports
        self.originAllowlist = originAllowlist
    }

    public static let `default` = AppConfig(
        ports: WebSocketServer.defaultPorts,
        originAllowlist: ["https://eporezi.purs.gov.rs"]
    )
}
