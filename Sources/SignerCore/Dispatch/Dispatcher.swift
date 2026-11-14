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
struct TerminalsPayload: Codable { let terminals: [Terminal] }
struct CertificatesPayload: Codable { let certificates: [Alias] }

/// SmartBox-compatible numeric error statuses.
enum ErrorStatus {
    static let terminalsGeneric = Status(1300)
    static let certificatesGeneric = Status(1400)
    static let middleware = Status(1350)
    static let pinIncorrect = Status(1440)
    static let pinLocked = Status(1441)
    static let unsupported = Status(1000)

    static func from(_ error: Error, generic: Status) -> Status {
        switch error as? CardError {
        case .pinIncorrect: return pinIncorrect
        case .pinLocked: return pinLocked
        case .middleware: return middleware
        default: return generic
        }
    }
}

public final class Dispatcher: MessageHandler {
    private let card: CardService
    private let encoder = JSONEncoder()

    public init(card: CardService) { self.card = card }

    private func emit<P: Codable>(_ op: Operation, _ payload: P, status: Status = .ok, _ send: (Data) -> Void) {
        if let data = try? encoder.encode(Envelope(operation: op, status: status, payload: payload)) {
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
        case .getTerminals:
            guard case .getTerminals(let input) = request.input else {
                emit(.getTerminals, EmptyPayload(), status: ErrorStatus.terminalsGeneric, send)
                return
            }
            do {
                emit(.getTerminals, TerminalsPayload(terminals: try card.terminals(providerId: input.providerId)), send)
            } catch {
                emit(.getTerminals, EmptyPayload(), status: ErrorStatus.from(error, generic: ErrorStatus.terminalsGeneric), send)
            }
        case .getCertificates:
            guard case .getCertificates(let input) = request.input else {
                emit(.getCertificates, EmptyPayload(), status: ErrorStatus.certificatesGeneric, send)
                return
            }
            // Single-provider MVP simplification: multi-provider would need a session-tracked
            // providerId. The real CardService must tolerate id 0 / empty providers without crashing.
            let providerId = card.providers().first?.id ?? 0
            do {
                let certs = try card.certificates(providerId: providerId, terminalId: input.terminalId, pin: input.pin)
                emit(.getCertificates, CertificatesPayload(certificates: certs), send)
            } catch {
                emit(.getCertificates, EmptyPayload(), status: ErrorStatus.from(error, generic: ErrorStatus.certificatesGeneric), send)
            }
        default:
            emit(request.operation, EmptyPayload(), status: ErrorStatus.unsupported, send)
        }
    }
}
