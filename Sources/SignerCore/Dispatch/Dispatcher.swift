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
    /// Card I/O is blocking (PIN prompt, APDUs): never run it on the NIO event loop. One serial queue
    /// for all connections also serializes access to the single card.
    private static let cardQueue = DispatchQueue(label: "signer.card", qos: .userInitiated)
    /// GET_SIGNED_XML carries no terminal id: use the one last used by GET_CERTIFICATES on THIS
    /// connection (default 0). Instances are per connection (see makeConnectionHandler).
    private let terminalLock = NSLock()
    private var lastTerminalId = 0

    public init(card: CardService) { self.card = card }

    /// Each connection gets its own Dispatcher so `lastTerminalId` is never shared across clients.
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
            break  // server-originated event; a client sending it gets no reply
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
            // Single-provider MVP simplification: multi-provider would need a session-tracked
            // providerId. The real CardService must tolerate id 0 / empty providers without crashing.
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
            // `send` hops back onto the channel's event loop itself.
            onCardQueue { [self] in
                signXml(input, terminalId: terminalId, send: send)
            }
        }
    }

    /// Single source of the provider id for every card call (single MUP provider today; a future
    /// multi-provider change only touches this). Must be called on the card queue. Falls back to 0 when no card.
    private func resolveProviderId() -> Int { card.providers().first?.id ?? 0 }

    /// The GET_SIGNED_XML success payload. TODO(phase-2): confirm GET_SIGNED_XML payload shape (bare string vs
    /// {signedXml:...}) against a real SmartBox frame. Currently the signed XML is emitted as a bare JSON string;
    /// swapping the shape is a one-line change here (e.g. return SignedXmlPayload(signedXml: xml)).
    /// The real portal protocol is base64 both ways (input confirmed live; OUTPUT base64 is inferred/symmetric and
    /// NOT yet confirmed live: flip here to `xml` if the portal expects the raw signed document).
    private struct SignedXmlPayload: Codable { let xml: String }
    // SmartBox wire shape (from decompiled jar): payload = {"xml": "<base64 of signed XML>"}.
    private func signedXmlPayload(_ xml: String) -> some Codable { SignedXmlPayload(xml: Data(xml.utf8).base64EncodedString()) }

    private func signXml(_ input: GetSignedXmlInput, terminalId: Int, send: @escaping (Data) -> Void) {
        do {
            // The portal sends the document base64-encoded; invalid base64 / non-UTF-8 -> generic sign error.
            guard let raw = Data(base64Encoded: input.xml, options: .ignoreUnknownCharacters),
                  let documentXML = String(data: raw, encoding: .utf8) else { throw CardError.generic }
            // One card session: cert + key FID resolved, one VERIFY, then sign (see CardService.withSigningKey).
            let xml = try card.withSigningKey(providerId: resolveProviderId(), terminalId: terminalId,
                                              alias: input.certificate, pin: input.pin) { der, sign in
                let info = try CertificateInfo(der: der)
                return try XMLDSigBuilder().build(documentXML: documentXML, certDER: der, issuer: info.issuer,
                                                  serial: info.serial, sign: sign)
            }
            emit(.getSignedXml, signedXmlPayload(xml), send)
        } catch {
            emit(.getSignedXml, EmptyPayload(), status: ErrorStatus.from(error, generic: ErrorStatus.signGeneric), send)
        }
    }
}
