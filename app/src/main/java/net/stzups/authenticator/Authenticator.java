package net.stzups.authenticator;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import net.stzups.authenticator.authentication.Database;
import net.stzups.netty.Server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;

public class Authenticator {
    private static final File file = new File("data.txt");

    public static void main(String[] args) throws Exception {
        System.err.println("Starting server...");
        Database database;
        if (!file.exists()) {
            database = new Database();
        } else {
            try (FileInputStream fileInputStream = new FileInputStream(file)) {
                database = new Database(Unpooled.wrappedBuffer(fileInputStream.getChannel().map(FileChannel.MapMode.READ_ONLY, 0, file.length())));
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
            database.serialize(byteBuf);
            try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
                byteBuf.readBytes(fileOutputStream, byteBuf.readableBytes());
            }
            System.err.println("Server stopped");
        }
    }
}
