package net.stzups.authenticator;

import io.netty.channel.ChannelFuture;
import net.stzups.authenticator.authentication.Database;
import net.stzups.netty.Server;

import java.io.*;

public class Authenticator {
    private static final File file = new File("data.txt");

    public static void main(String[] args) throws Exception {
        Database database;
        if (!file.exists()) {
            if (!file.createNewFile()) {
                throw new IOException("Could not create at " + file.getAbsolutePath());
            }
            database = new Database();
        } else {
            try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(file))) {
                database = (Database) objectInputStream.readObject();
            }
        }

        try (Server server = new Server(8080)) {
            Runtime.getRuntime().addShutdownHook(new Thread(server::close));

            ChannelFuture closeFuture = server.start(new HttpServerInitializer(new Config(), database));

            System.err.println("Started server");
            closeFuture.sync();
            try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(file))) {
                objectOutputStream.writeObject(database);
            }
            System.err.println("Server closed");
        }
    }
}
