package net.stzups.authenticator.database;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import net.stzups.authenticator.User;
import net.stzups.authenticator.authentication.Login;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.totp.TOTPGenerator;
import net.stzups.netty.util.DeserializationException;
import net.stzups.netty.util.NettyUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static net.stzups.netty.util.NettyUtils.*;

public class FileDatabase implements Database {
    private static final File file = new File("data.txt");

    private final Map<Long, Session> sessions; // session id to session
    private final Map<String, Login> logins; // user id to login
    private final Map<Long, User> users; // user id to user
    private final Map<Long, byte[]> totp; // user id to totp

    public FileDatabase(ByteBuf byteBuf) throws DeserializationException {
        sessions = readMap(byteBuf, ByteBuf::readLong, Session::new);
        logins = readMap(byteBuf, NettyUtils::readString, Login::new);
        users = readMap(byteBuf, ByteBuf::readLong, User::new);
        totp = readMap(byteBuf, ByteBuf::readLong, b -> readBytes(b, TOTPGenerator.SECRET_LENGTH));
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
            throw new Exception("Exception while serializing " + this, e);
        }
        System.err.println("Serialized in " + (System.nanoTime() - start) / 1000000 + "ms");
        try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            byteBuf.readBytes(fileOutputStream, byteBuf.readableBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void serialize(ByteBuf byteBuf) {
        writeMap(byteBuf, sessions, ByteBuf::writeLong, (b, session) -> session.serialize(b));
        writeMap(byteBuf, logins, NettyUtils::writeString, (b, login) -> login.serialize(b));
        writeMap(byteBuf, users, ByteBuf::writeLong, (b, user) -> user.serialize(b));
        writeMap(byteBuf, totp, ByteBuf::writeLong, ByteBuf::writeBytes);
    }

    public static FileDatabase getFileDatabase() throws Exception {
        if (!file.exists()) {
            return new FileDatabase();
        } else {
            try (FileInputStream fileInputStream = new FileInputStream(file)) {
                ByteBuf byteBuf = Unpooled.buffer();
                byteBuf.writeBytes(fileInputStream, (int) file.length());
                System.err.println("Deserializing...");
                long start = System.nanoTime();
                FileDatabase database =  new FileDatabase(byteBuf);
                System.err.println("Deserialized in " + (System.nanoTime() - start) / 1000000 + "ms");
                return database;
            }
        }
    }

    public FileDatabase() {
        sessions = new HashMap<>();
        logins = new HashMap<>();
        users = new HashMap<>();
        totp = new HashMap<>();
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
}
