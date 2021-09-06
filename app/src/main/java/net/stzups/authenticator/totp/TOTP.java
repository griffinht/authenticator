package net.stzups.authenticator.totp;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

// this might break because of y38
public class TOTP {
    private static final long T0 = 0;
    private static long unixTime() {
        return System.currentTimeMillis() / 1000L;
    }
    private static final int TIME_STEP = 30;

    private static long t(long unixTime, long t0, int timeStep) {
        return (unixTime - t0) / timeStep;
    }

    private static byte[] getBytes(long value) {
        ByteBuf byteBuf = Unpooled.copyLong(value);
        try {
            return byteBuf.array();
        } finally {
            byteBuf.release();
        }
    }

    public static byte[] getTotp(byte[] secret) {
        long t = t(unixTime(), T0, TIME_STEP);
        return HOTP.HOTP(secret, getBytes(t));
    }

    public static String getUri(byte[] secret) {
        return Otpauth.getUri(Otpauth.Type.TOTP, "label", secret, "issuer", Otpauth.Digits.EIGHT, 0, 30);
    }
}
