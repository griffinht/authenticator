package net.stzups.authenticator.totp;

import com.google.zxing.WriterException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import javax.imageio.ImageIO;
import java.io.File;
import java.io.IOException;
import java.util.Random;

// this might break because of y38
public class TOTP {
    public TOTP() {
        byte[] secret = new byte[16];
        new Random().nextBytes(secret);
        try {
            ImageIO.write(QrCode.getQrCode(getUri(secret)), "png", new File("out.png"));
        } catch (IOException | WriterException e) {
            throw new RuntimeException();
        }
        for (int i = -5; i < 5; i++) {
            int code = toCode(getTOTP(secret, i), 6);
            System.err.println(toCode(code, 6) + ", " + code);
        }
    }



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

    public static byte[] getTOTP(byte[] secret, int offset) {
        return HOTP.getHOTP(secret, getBytes(t(unixTime(), T0, TIME_STEP) + offset));
    }

    /**
     * Convert TOTP to short code
     */
    public static int toCode(byte[] totp, int length) {
        int offset = totp[totp.length - 1] & 0xf;
        int binary = ((totp[offset] & 0x7f) << 24)
                | ((totp[offset + 1] & 0xff) << 16)
                | ((totp[offset + 2] & 0xff) << 8)
                | (totp[offset + 3] & 0xff);
        return binary % (int) Math.pow(10, length);
    }

    /**
     * Pads with leading zeros that may be missing
     * For example: toCode(1234, 6) returns 001234
     */
    public static String toCode(int code, int length) {
        StringBuilder string = new StringBuilder(Integer.toString(code));
        while (string.length() != length) {
            string.insert(0, "0");
        }
        return string.toString();
    }

    public static String getUri(byte[] secret) {
        return Otpauth.getUri(Otpauth.Type.TOTP, "Corporation:Johnny%20Is%20Cool", secret, "google.com", 6, Otpauth.Algorithm.SHA1, null, 30);
    }
}
