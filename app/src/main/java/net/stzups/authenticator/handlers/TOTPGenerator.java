package net.stzups.authenticator.handlers;

import net.stzups.authenticator.totp.Otpauth;
import net.stzups.authenticator.totp.TOTP;

import java.security.SecureRandom;

public class TOTPGenerator {
    private static final int SECRET_LENGTH = 32;
    private static final int TIME_STEP = 30;
    private static final int OFFSET_START = -1;
    private static final int OFFSET_AMOUNT = 2;
    private static final int CODE_LENGTH = 6;


    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static byte[] generateSecret() {
        byte[] secret = new byte[SECRET_LENGTH];
        SECURE_RANDOM.nextBytes(secret);
        return secret;
    }

    public static boolean verify(byte[] secret, int code) {
        return TOTP.verify(secret, TIME_STEP, OFFSET_START, OFFSET_AMOUNT, code, CODE_LENGTH);
    }

    public static String getUri(byte[] secret, String label, String issuer) {
        return Otpauth.getUri(Otpauth.Type.TOTP, label, secret, issuer, CODE_LENGTH, Otpauth.Algorithm.SHA1, null, TIME_STEP);
    }
}
