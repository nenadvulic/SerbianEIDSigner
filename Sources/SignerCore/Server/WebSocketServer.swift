import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1
import NIOWebSocket

/// Application-side handler for a WebSocket connection. Text frames carry JSON.
/// `send` writes one text frame back to the connection that produced the call.
public protocol MessageHandler: AnyObject {
    /// Called once per accepted connection, right after the upgrade completes.
    func onOpen(send: @escaping (Data) -> Void)
    /// Called for each successfully decoded request frame on that connection.
    func handle(_ request: Request, send: @escaping (Data) -> Void)
}

public final class WebSocketServer {
    public static let defaultPorts = [17165, 20806, 65097]

    private let ports: [Int]
    // Task 4 enforces this at the handshake (shouldUpgrade); threaded through here only.
    private let originAllowlist: [String]
    private let handler: MessageHandler
    private var group: MultiThreadedEventLoopGroup?
    private var channel: Channel?

    public init(ports: [Int] = WebSocketServer.defaultPorts, originAllowlist: [String], handler: MessageHandler) {
        self.ports = ports
        self.originAllowlist = originAllowlist
        self.handler = handler
    }

    /// Binds 127.0.0.1 on the first free port of the list and returns it.
    public func start() throws -> Int {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let handler = self.handler
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let upgrader = NIOWebSocketServerUpgrader(
                    shouldUpgrade: { channel, _ in
                        // Task 4: Origin check goes here.
                        channel.eventLoop.makeSucceededFuture(HTTPHeaders())
                    },
                    upgradePipelineHandler: { channel, _ in
                        channel.pipeline.addHandler(WebSocketFrameHandler(handler: handler))
                    })
                let config: NIOHTTPServerUpgradeConfiguration = (
                    upgraders: [upgrader], completionHandler: { _ in })
                return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: config)
            }

        var lastError: Error = IOError(errnoCode: EADDRINUSE, reason: "no ports configured")
        for port in ports {
            do {
                let ch = try bootstrap.bind(host: "127.0.0.1", port: port).wait()
                self.group = group
                self.channel = ch
                return ch.localAddress?.port ?? port
            } catch {
                lastError = error  // address in use (or other bind failure): try next
            }
        }
        try? group.syncShutdownGracefully()
        throw lastError
    }

    public func stop() {
        try? channel?.close().wait()
        try? group?.syncShutdownGracefully()
        channel = nil
        group = nil
    }
}

private final class WebSocketFrameHandler: ChannelInboundHandler {
    typealias InboundIn = WebSocketFrame
    typealias OutboundOut = WebSocketFrame

    private let handler: MessageHandler
    private var buffer = ByteBuffer()
    private var assembling = false

    init(handler: MessageHandler) { self.handler = handler }

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
        // Pipeline is already upgraded when this handler is added.
        if context.channel.isActive { handler.onOpen(send: makeSend(context)) }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var frame = unwrapInboundIn(data)
        switch frame.opcode {
        case .text:
            buffer.clear(); buffer.writeBuffer(&frame.data); assembling = !frame.fin
            if frame.fin { dispatch(context) }
        case .continuation where assembling:
            buffer.writeBuffer(&frame.data); assembling = !frame.fin
            if frame.fin { dispatch(context) }
        case .ping:
            context.writeAndFlush(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .pong, data: frame.data)), promise: nil)
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
        // Malformed frames are dropped; error replies belong to the handler layer.
        guard let request = try? JSONDecoder().decode(Request.self, from: data) else { return }
        handler.handle(request, send: makeSend(context))
    }
}
