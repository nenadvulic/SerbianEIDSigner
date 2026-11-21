import XCTest
import NIOCore
import NIOPosix
@testable import SignerCore

final class TerminalRecorder {
    private let lock = NSLock()
    private var ids: [Int] = []
    func record(_ id: Int) { lock.lock(); ids.append(id); lock.unlock() }
    var recorded: [Int] { lock.lock(); defer { lock.unlock() }; return ids }
}

struct StubCardService: CardService {
    var terminalList: [Terminal] = []
    var certList: [Alias] = []
    var certError: CardError?
    var terminalError: CardError?
    var signCertDER: Data = PKCS15Fixtures.certSignature
    var signCertError: CardError?
    var signBytes = Data([0xDE, 0xAD, 0xBE, 0xEF])
    var signError: CardError?
    var recorder: TerminalRecorder?
    let sessionCount = SessionCounter()
    func providers() -> [Provider] { [Provider(id: 1, name: "MUP")] }
    func terminals(providerId: Int) throws -> [Terminal] {
        if let e = terminalError { throw e }
        return terminalList
    }
    func certificates(providerId: Int, terminalId: Int, pin: Secret) throws -> [Alias] {
        if let e = certError { throw e }
        return certList
    }
    func withSigningKey(providerId: Int, terminalId: Int, alias: Alias, pin: Secret,
                        build: (Data, (Data) throws -> Data) throws -> String) throws -> String {
        recorder?.record(terminalId)
        sessionCount.increment()
        if let e = signCertError { throw e }
        return try build(signCertDER) { _ in
            if let e = signError { throw e }
            return signBytes
        }
    }
}

final class SessionCounter {
    private let lock = NSLock()
    private var n = 0
    func increment() { lock.lock(); n += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
}

extension XCTestCase {
    func respond(_ d: MessageHandler, _ r: Request) throws -> (data: Data, onMain: Bool) {
        let exp = expectation(description: "response")
        var out: Data?
        var onMain = true
        d.handle(r) { out = $0; onMain = Thread.isMainThread; exp.fulfill() }
        wait(for: [exp], timeout: 5)
        return (try XCTUnwrap(out), onMain)
    }
}

func freeLoopbackPort() throws -> Int {
    let g = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    defer { try? g.syncShutdownGracefully() }
    let ch = try ServerBootstrap(group: g).bind(host: "127.0.0.1", port: 0).wait()
    let p = ch.localAddress!.port!
    try ch.close().wait()
    return p
}
