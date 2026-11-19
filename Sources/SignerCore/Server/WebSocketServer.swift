import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1
import NIOWebSocket

public protocol MessageHandler: AnyObject {

    func onOpen(send: @escaping (Data) -> Void)

    func handle(_ request: Request, send: @escaping (Data) -> Void)

    func makeConnectionHandler() -> MessageHandler
}

public extension MessageHandler {
    func makeConnectionHandler() -> MessageHandler { self }
}

public final class WebSocketServer {
    public static let defaultPorts = [17165, 20806, 65097]

    private let ports: [Int]

    private let originAllowlist: [String]
    private let handler: MessageHandler
    private var group: MultiThreadedEventLoopGroup?
    private var channels: [Channel] = []

    public init(ports: [Int] = WebSocketServer.defaultPorts, originAllowlist: [String], handler: MessageHandler) {
        self.ports = ports
        self.originAllowlist = originAllowlist
        self.handler = handler
    }

    public func start() throws -> Int {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let handler = self.handler
        let allowlist = self.originAllowlist
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let upgrader = NIOWebSocketServerUpgrader(
                    shouldUpgrade: { channel, head in

                        guard let origin = head.headers.first(name: "Origin"),
                              allowlist.contains(origin) else {
                            return channel.eventLoop.makeSucceededFuture(nil)
                        }
                        return channel.eventLoop.makeSucceededFuture(HTTPHeaders())
                    },
                    upgradePipelineHandler: { channel, _ in
                        channel.pipeline.removeHandler(name: ForbiddenHandler.name).flatMapError { _ in
                            channel.eventLoop.makeSucceededVoidFuture()
                        }.flatMap {
                            channel.pipeline.addHandler(WebSocketFrameHandler(handler: handler))
                        }
                    })
                let config: NIOHTTPServerUpgradeConfiguration = (
                    upgraders: [upgrader], completionHandler: { _ in })
                return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: config).flatMap {
                    channel.pipeline.addHandler(ForbiddenHandler(), name: ForbiddenHandler.name)
                }
            }

        var lastError: Error = IOError(errnoCode: EADDRINUSE, reason: "no ports configured")
        for port in ports {
            do {
                let v4 = try bootstrap.bind(host: "127.0.0.1", port: port).wait()
                let boundPort = v4.localAddress?.port ?? port
                do {
                    let v6 = try bootstrap.bind(host: "::1", port: boundPort).wait()
                    self.channels = [v4, v6]
                } catch {
                    if Self.isIPv6Unavailable(error) {
                        self.channels = [v4]
                    } else {
                        try? v4.close().wait()
                        throw error
                    }
                }
                self.group = group
                return boundPort
            } catch {
                lastError = error
            }
        }
        try? group.syncShutdownGracefully()
        throw lastError
    }

    private static func isIPv6Unavailable(_ error: Error) -> Bool {
        guard let io = error as? IOError else { return false }
        return io.errnoCode == EADDRNOTAVAIL || io.errnoCode == EAFNOSUPPORT
    }

    public func stop() {
        for c in channels { try? c.close().wait() }
        try? group?.syncShutdownGracefully()
        channels = []
        group = nil
    }
}

private final class ForbiddenHandler: ChannelInboundHandler, RemovableChannelHandler {
    static let name = "ForbiddenHandler"
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard case .head = unwrapInboundIn(data) else { return }
        var headers = HTTPHeaders()
        headers.add(name: "Content-Length", value: "0")
        headers.add(name: "Connection", value: "close")
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: .forbidden, headers: headers))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in context.close(promise: nil) }
    }
}

private final class WebSocketFrameHandler: ChannelInboundHandler {
    typealias InboundIn = WebSocketFrame
    typealias OutboundOut = WebSocketFrame

    private let handler: MessageHandler
    private var buffer = ByteBuffer()
    private var assembling = false

    init(handler: MessageHandler) { self.handler = handler.makeConnectionHandler() }

    private func makeSend(_ context: ChannelHandlerContext) -> (Data) -> Void {
        let channel = context.channel
        return { data in
            channel.eventLoop.execute {
                var out = channel.allocator.buffer(capacity: data.count)
                out.writeBytes(data)
                channel.writeAndFlush(WebSocketFrame(fin: true, opcode: .text, data: out), promise: nil)
            }
        }
    }

    func handlerAdded(context: ChannelHandlerContext) {

        if context.channel.isActive { handler.onOpen(send: makeSend(context)) }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var frame = unwrapInboundIn(data)
        switch frame.opcode {
        case .text:
            var payload = frame.unmaskedData
            buffer.clear(); buffer.writeBuffer(&payload); assembling = !frame.fin
            if frame.fin { dispatch(context) }
        case .continuation where assembling:
            var payload = frame.unmaskedData
            buffer.writeBuffer(&payload); assembling = !frame.fin
            if frame.fin { dispatch(context) }
        case .ping:
            context.writeAndFlush(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .pong, data: frame.unmaskedData)), promise: nil)
        case .connectionClose:
            context.writeAndFlush(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .connectionClose, data: context.channel.allocator.buffer(capacity: 0)))).whenComplete { _ in
                context.close(promise: nil)
            }
        default:
            break
        }
    }

    private func dispatch(_ context: ChannelHandlerContext) {
        let data = Data(buffer.readableBytesView)
        buffer.clear()

        guard let request = try? JSONDecoder().decode(Request.self, from: data) else { return }
        handler.handle(request, send: makeSend(context))
    }
}
