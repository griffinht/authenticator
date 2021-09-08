package net.stzups.authenticator.authentication;

import io.netty.buffer.ByteBuf;

import java.util.Arrays;

public class Login {
    private final byte[] hash;
    private final byte[] salt;
    public final long user;

    public Login(ByteBuf byteBuf) {
        hash = new byte[PasswordUtil.HASH_LENGTH];
        byteBuf.readBytes(hash);
        salt = new byte[PasswordUtil.SALT_LENGTH];
        byteBuf.readBytes(salt);
        user = byteBuf.readLong();
    }

    public void serialize(ByteBuf byteBuf) {
        byteBuf.writeBytes(hash);
        byteBuf.writeBytes(salt);
        byteBuf.writeLong(user);
    }

    public Login(byte[] password, long user) {
        byte[][] bytes = PasswordUtil.hash(password);
        hash = bytes[0];
        salt = bytes[1];
        this.user = user;
    }

    public static boolean verify(Login login, byte[] password) {
        return Arrays.equals(
                        PasswordUtil.hash(
                                password,
                                login != null ? login.salt : null
                        ), login != null ? login.hash : null
                );
    }
}
