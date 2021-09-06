package net.stzups.authenticator.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HOTP {
    private static Object truncate(byte[] hmacSHA1) {
        return null;
    }
    public static Object HOTP(byte[] key, byte[] message, long counter) {
        return null;
    }

    public static byte[] hmacSha1(byte[] key, byte[] value) {
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA1");
        try {
            mac.init(secretKeySpec);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(value);
    }
}
