package net.stzups.authenticator.authentication;

import io.netty.handler.codec.http.cookie.Cookie;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Session {
    static final int tokenLength = 128 / 8;

    private static final SecureRandom secureRandom = new SecureRandom();

    public final long id = secureRandom.nextLong();
    public byte[] hash;

    public Cookie generate() {
        byte[] token = new byte[tokenLength];
        secureRandom.nextBytes(token);
        Cookie cookie = SessionCookie.createSessionCookie(id, token);
        hash = hash(token);

        return cookie;
    }

    public static boolean verify(Session session, byte[] token) {
        return Arrays.equals(hash(token), session != null ? session.hash : null);
    }

    private static byte[] hash(byte[] token) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Exception while getting algorithm SHA-256", e);
        }
        byte[] hash = messageDigest.digest(token);
        // might as well clear token because it should not be reused
        Arrays.fill(token, (byte) 0);
        return hash;
    }
}
