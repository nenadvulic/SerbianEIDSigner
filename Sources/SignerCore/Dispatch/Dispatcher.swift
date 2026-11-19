import Foundation

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

enum ErrorStatus {
    static let terminalsGeneric = Status(1300)
    static let certificatesGeneric = Status(1400)
    static let middleware = Status(1350)
    static let pinIncorrect = Status(1440)
    static let pinLocked = Status(1441)
    static let signGeneric = Status(1500)

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

    private static let cardQueue = DispatchQueue(label: "signer.card", qos: .userInitiated)

    private let terminalLock = NSLock()
    private var lastTerminalId = 0

    public init(card: CardService) { self.card = card }

    public func makeConnectionHandler() -> MessageHandler { Dispatcher(card: card) }

    private func onCardQueue(_ work: @escaping () -> Void) { Self.cardQueue.async(execute: work) }

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
        case .onOpenEvent:
            break
        case .getInfo:
            emit(.getInfo, EmptyPayload(), send)
        case .getProviders:
            onCardQueue { [self] in
                emit(.getProviders, ProvidersPayload(providers: card.providers()), send)
            }
        case .getTerminals:
            guard case .getTerminals(let input) = request.input else {
                emit(.getTerminals, EmptyPayload(), status: ErrorStatus.terminalsGeneric, send)
                return
            }
            onCardQueue { [self] in
                do {
                    emit(.getTerminals, TerminalsPayload(terminals: try card.terminals(providerId: resolveProviderId())), send)
                } catch {
                    emit(.getTerminals, EmptyPayload(), status: ErrorStatus.from(error, generic: ErrorStatus.terminalsGeneric), send)
                }
            }
        case .getCertificates:
            guard case .getCertificates(let input) = request.input else {
                emit(.getCertificates, EmptyPayload(), status: ErrorStatus.certificatesGeneric, send)
                return
            }

            terminalLock.lock(); lastTerminalId = input.terminalId; terminalLock.unlock()
            onCardQueue { [self] in
                do {
                    let certs = try card.certificates(providerId: resolveProviderId(), terminalId: input.terminalId, pin: input.pin)
                    emit(.getCertificates, CertificatesPayload(certificates: certs), send)
                } catch {
                    emit(.getCertificates, EmptyPayload(), status: ErrorStatus.from(error, generic: ErrorStatus.certificatesGeneric), send)
                }
            }
        case .getSignedXml:
            guard case .getSignedXml(let input) = request.input else {
                emit(.getSignedXml, EmptyPayload(), status: ErrorStatus.signGeneric, send)
                return
            }
            terminalLock.lock(); let terminalId = lastTerminalId; terminalLock.unlock()

            onCardQueue { [self] in
                signXml(input, terminalId: terminalId, send: send)
            }
        }
    }

    private func resolveProviderId() -> Int { card.providers().first?.id ?? 0 }

    private struct SignedXmlPayload: Codable { let xml: String }

    private func signedXmlPayload(_ xml: String) -> some Codable { SignedXmlPayload(xml: Data(xml.utf8).base64EncodedString()) }

    private func signXml(_ input: GetSignedXmlInput, terminalId: Int, send: @escaping (Data) -> Void) {
        do {
            guard let raw = Data(base64Encoded: input.xml, options: .ignoreUnknownCharacters),
                  let documentXML = String(data: raw, encoding: .utf8) else { throw CardError.generic }
            let xml = try card.withSigningKey(providerId: resolveProviderId(), terminalId: terminalId,
                                              alias: input.certificate, pin: input.pin) { der, sign in
                let info = try CertificateInfo(der: der)
                return try XMLDSigBuilder().build(documentXML: documentXML, certDER: der, issuer: info.issuer,
                                                  serial: info.serial, subject: info.subject, sign: sign)
            }
            emit(.getSignedXml, signedXmlPayload(xml), send)
        } catch {
            emit(.getSignedXml, EmptyPayload(), status: ErrorStatus.from(error, generic: ErrorStatus.signGeneric), send)
        }
    }
}
