import Foundation

/// ON_OPEN_EVENT identity. SmartBox-compatible defaults for drop-in use with the
/// e-porezi portal; change here only.
public enum AppInfo {
    public static let appName = "SmartBox"
    public static let appVersion = "2.0.0"
    public static let appBuild = 1
    public static var osName: String {
        #if os(macOS)
        return "Mac OS X"
        #elseif os(Linux)
        return "Linux"
        #else
        return "Windows"
        #endif
    }
}

struct OpenPayload: Codable {
    let appName: String
    let appVersion: String
    let appBuild: Int
    let osName: String
}
struct EmptyPayload: Codable {}
struct ProvidersPayload: Codable { let providers: [Provider] }

public final class Dispatcher: MessageHandler {
    private let card: CardService
    private let encoder = JSONEncoder()

    public init(card: CardService) { self.card = card }

    private func emit<P: Codable>(_ op: Operation, _ payload: P, _ send: (Data) -> Void) {
        if let data = try? encoder.encode(Envelope(operation: op, status: .ok, payload: payload)) {
            send(data)
        }
    }

    public func onOpen(send: @escaping (Data) -> Void) {
        emit(.onOpenEvent, OpenPayload(appName: AppInfo.appName, appVersion: AppInfo.appVersion,
                                       appBuild: AppInfo.appBuild, osName: AppInfo.osName), send)
    }

    public func handle(_ request: Request, send: @escaping (Data) -> Void) {
        switch request.operation {
        case .getInfo:
            emit(.getInfo, EmptyPayload(), send)
        case .getProviders:
            emit(.getProviders, ProvidersPayload(providers: card.providers()), send)
        default:
            break // later tasks
        }
    }
}
