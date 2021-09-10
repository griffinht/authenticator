package net.stzups.authenticator;

import io.netty.channel.ChannelFuture;
import net.stzups.authenticator.database.Database;
import net.stzups.authenticator.database.FileDatabase;
import net.stzups.netty.Server;

public class Authenticator {

    public static void main(String[] args) throws Exception {
        System.err.println("Starting server...");

        try (Server server = new Server(8080);
             Database database = new FileDatabase()) {
            Runtime.getRuntime().addShutdownHook(new Thread(server::close));

            ChannelFuture closeFuture = server.start(new HttpServerInitializer(new Config(), database));

            System.err.println("Started server");
            closeFuture.sync();
            System.err.println("Stopping server...");


            System.err.println("Server stopped");
        }
    }

}
