package net.stzups.authenticator.database;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import net.stzups.authenticator.User;
import net.stzups.authenticator.authentication.Login;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.totp.TOTPGenerator;
import net.stzups.netty.util.Deserializer;
import net.stzups.netty.util.NettyUtils;
import net.stzups.netty.util.Serializer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

public class FileDatabase implements Database {
    private static final File file = new File("data.txt");

    private final Map<Long, Session> sessions; // session id to session
    private final Map<String, Login> logins; // user id to login
    private final Map<Long, User> users; // user id to user
    private final Map<Long, byte[]> totp; // user id to totp

    public FileDatabase(ByteBuf byteBuf) {
        sessions = readHashMap32(byteBuf, ByteBuf::readLong, Session::new);
        logins = readHashMap32(byteBuf, NettyUtils::readString8, Login::new);
        users = readHashMap32(byteBuf, ByteBuf::readLong, User::new);
        totp = readHashMap32(byteBuf, ByteBuf::readLong, b -> readBytes(b, TOTPGenerator.SECRET_LENGTH));
    }

    @Override
    public void close() throws Exception {

        if (!file.exists() && !file.createNewFile()) {
            throw new IOException("Could not create at " + file.getAbsolutePath());
        }
        ByteBuf byteBuf = Unpooled.buffer();
        System.err.println("Serializing...");
        long start = System.nanoTime();
        try {
            serialize(byteBuf);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.err.println("Serialized in " + (System.nanoTime() - start) / 1000000 + "ms");
        try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            byteBuf.readBytes(fileOutputStream, byteBuf.readableBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void serialize(ByteBuf byteBuf) {
        writeHashMap32(byteBuf, sessions, ByteBuf::writeLong, (b, session) -> session.serialize(b));
        writeHashMap32(byteBuf, logins, NettyUtils::writeString8, (b, login) -> login.serialize(b));
        writeHashMap32(byteBuf, users, ByteBuf::writeLong, (b, user) -> user.serialize(b));
        writeHashMap32(byteBuf, totp, ByteBuf::writeLong, ByteBuf::writeBytes);
    }

    public FileDatabase() {
        if (!file.exists()) {
            generateGarbage(this);
        } else {
            try (FileInputStream fileInputStream = new FileInputStream(file)) {
                ByteBuf byteBuf = Unpooled.buffer();
                byteBuf.writeBytes(fileInputStream, (int) file.length());
                System.err.println("Deserializing...");
                long start = System.nanoTime();
                database = new FileDatabase(byteBuf);
                System.err.println("Deserialized in " + (System.nanoTime() - start) / 1000000 + "ms");
            }
        }
        sessions = new HashMap<>();
        logins = new HashMap<>();
        users = new HashMap<>();
        totp = new HashMap<>();
    }

    public static byte[] readBytes(ByteBuf byteBuf, int length) {
        byte[] bytes = new byte[length];
        byteBuf.readBytes(bytes);
        return bytes;
    }

    public static <K, V, KK extends Deserializer<K>, VV extends Deserializer<V>> HashMap<K, V> readHashMap32(ByteBuf byteBuf, KK kk, VV vv) {
        int length = byteBuf.readInt();
        HashMap<K, V> map = new HashMap<>();

        for (int i = 0; i < length; i++) {
            map.put(kk.deserialize(byteBuf), vv.deserialize(byteBuf));
        }

        return map;
    }

    public static <K, V, KK extends Serializer<K>, VV extends Serializer<V>> void writeHashMap32(ByteBuf byteBuf, Map<K, V> map, KK kk, VV vv) {
        byteBuf.writeInt(map.size());

        for (Map.Entry<K, V> entry : map.entrySet()) {
            kk.serialize(byteBuf, entry.getKey());
            vv.serialize(byteBuf, entry.getValue());
        }
    }

    public Session getSession(long id) {
        return sessions.get(id);
    }

    public void addSession(Session session) {
        sessions.put(session.id, session);
    }

    public void removeSession(Session session) {
       sessions.remove(session.id);
    }
    public void addUser(User user) {
        users.put(user.id, user);
    }

    public User getUser(long id) {
        return users.get(id);
    }
    public void addLogin(String username, Login login) {
        logins.put(username, login);
    }

    public Login getLogin(String username) {
        return logins.get(username);
    }

    public void setTotp(long user, byte[] secret) {
        totp.put(user, secret);
    }
    public void addTotp(long user, byte[] secret) {
        totp.put(user, secret);
    }

    public boolean hasTotp(long user) {
        return totp.containsKey(user);
    }

    public byte[] getTotp(long user) {
        return totp.get(user);
    }

    public void removeTotp(long user) {
        totp.remove(user);
    }




    private static Random random = new Random();
    public static String randomString() {
        return new UUID(random.nextLong(), random.nextLong()).toString();
    }
    private static void generateGarbage(FileDatabase database) {
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
    }
}
