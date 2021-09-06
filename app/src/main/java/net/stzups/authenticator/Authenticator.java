package net.stzups.authenticator;

import io.netty.channel.ChannelFuture;
import net.stzups.authenticator.authentication.Database;
import net.stzups.netty.Server;

public class Authenticator {


    public static void main(String[] args) throws Exception {
        try (Server server = new Server(8080)) {
            Runtime.getRuntime().addShutdownHook(new Thread(server::close));

            ChannelFuture closeFuture = server.start(new HttpServerInitializer(new Config(), new Database()));

            System.err.println("Started server");
            closeFuture.sync();
            System.err.println("Server closed");
        }
    }
}
