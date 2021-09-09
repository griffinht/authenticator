package net.stzups.authenticator;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.ByteBufOutputStream;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Login;
import net.stzups.authenticator.totp.TOTPGenerator;
import net.stzups.netty.Server;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.UUID;

public class Authenticator {
    private static final File file = new File("data.txt");

    private static Random random = new Random();
    public static String randomString() {
        return new UUID(random.nextLong(), random.nextLong()).toString();
    }
    public static void main(String[] args) throws Exception {
        System.err.println("Starting server...");
        Database database;
        if (!file.exists()) {
            database = new Database();
            int length = 500000;
            long last = System.currentTimeMillis();
            for (int i = 0; i < length; i++) {
                if (i % 100 == 0 && System.currentTimeMillis() - last > 1000) {
                    last = System.currentTimeMillis();
                    System.err.println("Generating... (" + i + "/" + length + ")");
                }
                User user = new User(randomString());
                database.addUser(user);
                database.addLogin(randomString(), new Login(randomString().getBytes(StandardCharsets.UTF_8), user.id));
                database.addTotp(user.id, TOTPGenerator.generateSecret());
            }
        } else {
            try (FileInputStream fileInputStream = new FileInputStream(file)) {
                ByteBuf byteBuf = Unpooled.buffer();
                byteBuf.writeBytes(fileInputStream, (int) file.length());
                System.err.println("Deserializing...");
                long start = System.nanoTime();
                database = new Database(byteBuf);
                System.err.println("Deserialized in " + (System.nanoTime() - start) / 1000000 + "ms");
            }
        }

        try (Server server = new Server(8080)) {
            Runtime.getRuntime().addShutdownHook(new Thread(server::close));

            ChannelFuture closeFuture = server.start(new HttpServerInitializer(new Config(), database));

            System.err.println("Started server");
            closeFuture.sync();
            System.err.println("Stopping server...");

            if (!file.exists() && !file.createNewFile()) {
                throw new IOException("Could not create at " + file.getAbsolutePath());
            }
            ByteBuf byteBuf = Unpooled.buffer();
            System.err.println("Serializing...");
            long start = System.nanoTime();
            try {
                database.serialize(byteBuf);
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.err.println("Serialized in " + (System.nanoTime() - start) / 1000000 + "ms");
            try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
                byteBuf.readBytes(fileOutputStream, byteBuf.readableBytes());
            } catch (Exception e) {
                e.printStackTrace();
            }

            System.err.println("Server stopped");
        }
    }
}
