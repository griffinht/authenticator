package net.stzups.authenticator.authentication;

import java.util.Arrays;

public class Login {
    private final byte[] hash;
    private final byte[] salt;

    public Login(byte[] password) {
        byte[][] bytes = PasswordUtil.hash(password);
        hash = bytes[0];
        salt = bytes[1];
    }

    public static boolean verify(Login login, byte[] password) {
        return Arrays.equals(PasswordUtil.hash(password, login != null ? login.salt : null), login != null ? login.hash : null);
    }
}
