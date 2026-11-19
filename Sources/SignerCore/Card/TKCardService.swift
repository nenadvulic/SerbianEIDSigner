import Foundation
import CryptoTokenKit

final class SmartCardTransport: APDUTransport {
    private let card: TKSmartCard
    init(card: TKSmartCard) { self.card = card; card.cla = 0x00 }

    func transmit(_ apdu: APDU) throws -> APDUResponse {
        let le: Int?
        switch apdu.le {
        case nil: le = nil
        case 256?: le = 0
        case let v?: le = v
        }
        do {
            let (sw, data) = try card.send(ins: apdu.ins, p1: apdu.p1, p2: apdu.p2,
                                           data: apdu.data.isEmpty ? nil : Data(apdu.data), le: le)
            return APDUResponse(data: [UInt8](data), sw: sw)
        } catch {
            throw APDUError.transport(String(describing: error))
        }
    }
}

public final class TKCardService: CardService {
    private static let mupProvider = Provider(id: 0, name: "MUP")

    public init() {}

    private func occupiedSlots() -> [(name: String, slot: TKSmartCardSlot)] {
        guard let manager = TKSmartCardSlotManager.default else { return [] }
        var out: [(String, TKSmartCardSlot)] = []
        for name in manager.slotNames {
            var slot: TKSmartCardSlot?
            let done = DispatchSemaphore(value: 0)
            manager.getSlot(withName: name) { slot = $0; done.signal() }
            done.wait()
            if let slot, slot.state == .validCard, let atr = slot.atr, PKCS15.isMUPATR([UInt8](atr.bytes)) {
                out.append((name, slot))
            }
        }
        return out
    }

    public func providers() -> [Provider] {
        occupiedSlots().isEmpty ? [] : [Self.mupProvider]
    }

    public func terminals(providerId: Int) throws -> [Terminal] {
        guard providerId == Self.mupProvider.id else { throw CardError.middleware }
        return occupiedSlots().enumerated().map { Terminal(id: $0.offset, name: $0.element.name) }
    }

    public func certificates(providerId: Int, terminalId: Int, pin: Secret) throws -> [Alias] {
        guard providerId == Self.mupProvider.id else { throw CardError.middleware }
        let slots = occupiedSlots()
        guard slots.indices.contains(terminalId), let card = slots[terminalId].slot.makeSmartCard() else {
            throw CardError.generic
        }
        let transport = SmartCardTransport(card: card)
        do {
            return try card.withSession {
                try PKCS15.signingAliases(from: transport, pin: pin)
            }
        } catch let e as CardError {
            throw e
        } catch {
            throw CardError.generic
        }
    }

    private func withTransport<T>(providerId: Int, terminalId: Int, _ body: @escaping (APDUTransport) throws -> T) throws -> T {
        guard providerId == Self.mupProvider.id else { throw CardError.middleware }
        let slots = occupiedSlots()
        guard slots.indices.contains(terminalId), let card = slots[terminalId].slot.makeSmartCard() else {
            throw CardError.generic
        }
        let transport = SmartCardTransport(card: card)
        do {
            return try card.withSession { try body(transport) }
        } catch let e as CardError {
            throw e
        } catch {
            throw CardError.generic
        }
    }

    public func withSigningKey(providerId: Int, terminalId: Int, alias: Alias, pin: Secret,
                               build: (_ certDER: Data, _ sign: (Data) throws -> Data) throws -> String) throws -> String {
        try withoutActuallyEscaping(build) { build in
            try withTransport(providerId: providerId, terminalId: terminalId) {
                try PKCS15.withSigningKey(from: $0, pin: pin, alias: alias, build)
            }
        }
    }
}
