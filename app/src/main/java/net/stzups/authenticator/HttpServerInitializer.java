package net.stzups.authenticator;

import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpContentCompressor;
import io.netty.handler.stream.ChunkedWriteHandler;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.handlers.AuthenticationHandler;
import net.stzups.authenticator.handlers.LoginHandler;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.DefaultHttpServerHandler;

import javax.net.ssl.SSLException;

public class HttpServerInitializer extends net.stzups.netty.http.HttpServerInitializer {
    private final LoginHandler loginHandler;
    private final AuthenticationHandler authenticationHandler;

    protected HttpServerInitializer(Config config, Database database) throws SSLException {
        super(config);
        this.loginHandler = new LoginHandler(database);
        this.authenticationHandler = new AuthenticationHandler(database);
    }


    @Override
    protected void initChannel(SocketChannel channel) {
    TestLog.setLogger(channel);
    super.initChannel(channel);

    channel.pipeline()
            .addLast(new HttpContentCompressor())
            .addLast(new ChunkedWriteHandler())
            .addLast(new DefaultHttpServerHandler()
                    .addLast(loginHandler)
                    .addLast(authenticationHandler)
            );
    }
}
