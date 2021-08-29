package net.stzups.authenticator.authentication;

import java.util.Arrays;

public class Login {
    private static final byte[] DUMMY = new byte[PasswordUtil.hashLength];

    private final byte[] hash;

    public Login(byte[] password) {
        this.hash = PasswordUtil.hash(password);
    }

    public static boolean verify(Login login, byte[] password) {
        byte[] hash;
        if (login != null) hash = login.hash; else hash = DUMMY;
        // always return false if hash is dummy
        return Arrays.equals(PasswordUtil.hash(password), hash) && hash != DUMMY;
    }
}
