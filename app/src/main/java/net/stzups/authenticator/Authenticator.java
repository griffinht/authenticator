package net.stzups.authenticator;

import io.netty.channel.ChannelFuture;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.stream.ChunkedWriteHandler;
import net.stzups.netty.Server;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.DefaultHttpServerHandler;
import net.stzups.netty.http.HttpServerInitializer;

public class Authenticator {


    public static void main(String[] args) throws Exception {
        try (Server server = new Server(8080)) {
            Runtime.getRuntime().addShutdownHook(new Thread(server::close));

            ChannelFuture closeFuture = server.start(new HttpServerInitializer(new Config()) {
                @Override
                protected void initChannel(SocketChannel channel) {
                    TestLog.setLogger(channel);
                    super.initChannel(channel);

                    channel.pipeline()
                            .addLast(new HttpContentCompressor())
                            .addLast(new ChunkedWriteHandler())
                            .addLast(new DefaultHttpServerHandler()
                                .addLast(new AuthenticationHandler())
                            );
                }
            });

            System.err.println("Started server");
            closeFuture.sync();
            System.err.println("Server closed");
        }
    }
}
