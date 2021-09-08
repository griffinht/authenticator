package net.stzups.authenticator.authentication;

import io.netty.buffer.ByteBuf;
import net.stzups.authenticator.User;
import net.stzups.authenticator.totp.TOTPGenerator;
import net.stzups.netty.util.Deserializer;
import net.stzups.netty.util.NettyUtils;
import net.stzups.netty.util.Serializer;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class Database {
    private final Map<Long, Session> sessions; // session id to session
    private final Map<String, Login> logins; // user id to login
    private final Map<Long, User> users; // user id to user
    private final Map<Long, byte[]> totp; // user id to totp

    public Database(ByteBuf byteBuf) {
        sessions = readHashMap8(byteBuf, ByteBuf::readLong, Session::new);
        logins = readHashMap8(byteBuf, NettyUtils::readString8, Login::new);
        users = readHashMap8(byteBuf, ByteBuf::readLong, User::new);
        totp = readHashMap8(byteBuf, ByteBuf::readLong, b -> readBytes(b, TOTPGenerator.SECRET_LENGTH));
    }

    public void serialize(ByteBuf byteBuf) {
        writeHashMap8(byteBuf, sessions, ByteBuf::writeLong, (b, session) -> session.serialize(b));
        writeHashMap8(byteBuf, logins, NettyUtils::writeString8, (b, login) -> login.serialize(b));
        writeHashMap8(byteBuf, users, ByteBuf::writeLong, (b, user) -> user.serialize(b));
        writeHashMap8(byteBuf, totp, ByteBuf::writeLong, ByteBuf::writeBytes);
    }

    public Database() {
        sessions = new HashMap<>();
        logins = new HashMap<>();
        users = new HashMap<>();
        totp = new HashMap<>();
        User user = new User("user");
        users.put(user.id, user);
        logins.put("admin", new Login("password".getBytes(StandardCharsets.UTF_8), user.id));
    }

    public static byte[] readBytes(ByteBuf byteBuf, int length) {
        byte[] bytes = new byte[length];
        byteBuf.readBytes(bytes);
        return bytes;
    }

    public static <K, V, KK extends Deserializer<K>, VV extends Deserializer<V>> HashMap<K, V> readHashMap8(ByteBuf byteBuf, KK kk, VV vv) {
        int length = byteBuf.readUnsignedByte();
        HashMap<K, V> map = new HashMap<>();

        for (int i = 0; i < length; i++) {
            map.put(kk.deserialize(byteBuf), vv.deserialize(byteBuf));
        }

        return map;
    }

    public static <K, V, KK extends Serializer<K>, VV extends Serializer<V>> void writeHashMap8(ByteBuf byteBuf, Map<K, V> map, KK kk, VV vv) {
        byteBuf.writeByte((byte) map.size());

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

    public User getUser(long id) {
        return users.get(id);
    }

    public Login getLogin(String username) {
        return logins.get(username);
    }

    public void setTotp(long user, byte[] secret) {
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
