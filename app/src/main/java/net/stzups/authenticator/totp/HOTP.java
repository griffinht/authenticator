package net.stzups.authenticator.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HOTP {
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

    public static byte[] getHOTP(byte[] secret, byte[] movingFactor) {
        return hmacSha1(secret, movingFactor);
    }
}
