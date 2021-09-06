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

    public static byte[] getTotp(byte[] secret) {
        return HOTP.HOTP(secret, getBytes(t(unixTime(), T0, TIME_STEP)));
    }

    public static String getUri(byte[] secret) {
        return Otpauth.getUri(Otpauth.Type.TOTP, "corporationn:john@corpocomc.com", secret, "issuerCorp", Otpauth.Digits.SIX, Otpauth.Algorithm.SHA1, 0, 30);
    }
}
