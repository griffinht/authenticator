package net.stzups.authenticator;

import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.cookie.ClientCookieDecoder;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.CookieDecoder;
import io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import io.netty.handler.stream.ChunkedWriteHandler;
import net.stzups.netty.Server;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.DefaultHttpServerHandler;
import net.stzups.netty.http.HttpServerInitializer;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.NotFoundException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;
import net.stzups.netty.http.handler.HttpHandler;

import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class Authenticator {
    private static final String COOKIE_NAME = "session";

    public static void main(String[] args) throws Exception {
        try (Server server = new Server(8080)) {
            Runtime.getRuntime().addShutdownHook(new Thread(server::close));

            ChannelFuture closeFuture = server.start(new HttpServerInitializer(new HttpServerInitializer.Config() {
                @Override
                public boolean getSSL() {
                    return false;
                }

                @Override
                public String getSSLRootPath() {
                    return null;
                }

                @Override
                public String getSSLPath() {
                    return null;
                }

                @Override
                public boolean getDebugLogTraffic() {
                    return false;
                }
            }) {
                @Override
                protected void initChannel(SocketChannel channel) {
                    TestLog.setLogger(channel);
                    super.initChannel(channel);

                    channel.pipeline()
                            .addLast(new HttpContentCompressor())
                            .addLast(new ChunkedWriteHandler())
                            .addLast(new DefaultHttpServerHandler()
                            .addLast(new HttpHandler("/auth") {
                                @Override
                                public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request, HttpResponse response) throws HttpException {
                                    //todo verify that this is actually coming from the proxy
                                    //System.out.println(request.headers());
                                    String cookiesHeader = request.headers().get(HttpHeaderNames.COOKIE);
                                    if (cookiesHeader == null) {
                                        throw new UnauthorizedException("Missing any cookie");

                                    }

                                    Set<Cookie> cookies = ServerCookieDecoder.STRICT.decode(cookiesHeader);
                                    for (Cookie cookie : cookies) {
                                        if (!cookie.name().equals(COOKIE_NAME)) {
                                            continue;
                                        }

                                        System.out.println(cookie.value());
                                        response.setStatus(HttpResponseStatus.OK);
                                        HttpUtils.send(ctx, request, response);
                                        return true;
                                    }
                                    throw new UnauthorizedException("Missing " + COOKIE_NAME + " cookie");
                                }
                            }));
                }
            });

            System.err.println("Started server");
            closeFuture.sync();
            System.err.println("Server closed");
        }
    }
}
