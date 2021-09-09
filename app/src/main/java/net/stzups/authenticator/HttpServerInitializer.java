package net.stzups.authenticator;

import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpContentCompressor;
import io.netty.handler.stream.ChunkedWriteHandler;
import net.stzups.authenticator.database.Database;
import net.stzups.authenticator.handlers.*;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.DefaultHttpServerHandler;
import net.stzups.netty.http.handler.HttpHandler;

import javax.net.ssl.SSLException;

public class HttpServerInitializer extends net.stzups.netty.http.HttpServerInitializer {
    private final HttpHandler[] httpHandlers;

    protected HttpServerInitializer(Config config, Database database) throws SSLException {
        super(config);
        this.httpHandlers = new HttpHandler[]{
                new LoginHandler(database),
                new AuthenticationHandler(database),
                new LogoutHandler(database),
                new OtpHandler(database),
                new UserHandler(database)
        };
    }


    @Override
    protected void initChannel(SocketChannel channel) {
    TestLog.setLogger(channel);
    super.initChannel(channel);

    channel.pipeline()
            .addLast(new HttpContentCompressor())
            .addLast(new ChunkedWriteHandler())
            .addLast(new DefaultHttpServerHandler()
                    .addLast(httpHandlers)
            );
    }
}
