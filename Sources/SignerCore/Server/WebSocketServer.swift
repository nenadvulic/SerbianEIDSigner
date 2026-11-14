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
    /// Called once per accepted connection to get the handler for that connection, so per-connection
    /// state (e.g. the selected terminal) is never shared between clients. Default: the handler itself.
    func makeConnectionHandler() -> MessageHandler
}

public extension MessageHandler {
    func makeConnectionHandler() -> MessageHandler { self }
}

public final class WebSocketServer {
    public static let defaultPorts = [17165, 20806, 65097]

    private let ports: [Int]
    // Enforced at the handshake: upgrade only when the request Origin is listed.
    private let originAllowlist: [String]
    private let handler: MessageHandler
    private var group: MultiThreadedEventLoopGroup?
    private var channels: [Channel] = []

    public init(ports: [Int] = WebSocketServer.defaultPorts, originAllowlist: [String], handler: MessageHandler) {
        self.ports = ports
        self.originAllowlist = originAllowlist
        self.handler = handler
    }

    /// Binds both loopback addresses (127.0.0.1 and ::1) on the first port of the list that can be bound,
    /// and returns it. The portal connects to `ws://localhost:PORT` and Chromium on macOS tries `::1` first.
    /// A port is only taken when 127.0.0.1 AND ::1 both bind; if IPv6 loopback is unavailable on the host
    /// (EADDRNOTAVAIL/EAFNOSUPPORT) the server degrades to IPv4-only rather than failing to start.
    public func start() throws -> Int {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let handler = self.handler
        let allowlist = self.originAllowlist
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let upgrader = NIOWebSocketServerUpgrader(
                    shouldUpgrade: { channel, head in
                        // Missing or non-allowlisted Origin: decline (nil) so the request
                        // falls through to ForbiddenHandler, which answers 403.
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
                        throw error  // ::1 busy on this port: try next
                    }
                }
                self.group = group
                return boundPort
            } catch {
                lastError = error  // address in use (or other bind failure): try next
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

/// Receives only requests that were NOT upgraded (declined handshake) and answers 403.
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
        // Pipeline is already upgraded when this handler is added.
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
        // Malformed frames are dropped; error replies belong to the handler layer.
        guard let request = try? JSONDecoder().decode(Request.self, from: data) else { return }
        handler.handle(request, send: makeSend(context))
    }
}
