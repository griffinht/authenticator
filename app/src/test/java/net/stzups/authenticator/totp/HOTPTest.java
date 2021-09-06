package net.stzups.authenticator.totp;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class HOTPTest {
    @Test
    public void hmacSha1() {
        // random tests from random stackoverflow question
        // https://stackoverflow.com/q/6312544/11975214
        byte[] value = "helloworld".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(
                HOTP.hmacSha1("mykey".getBytes(StandardCharsets.UTF_8), value),
                Hex.decode("74ae5a4a3d9996d5918defc2c3d475471bbf59ac"));
        assertArrayEquals(
                HOTP.hmacSha1("PRIE7$oG2uS-Yf17kEnUEpi5hvW/#AFo".getBytes(StandardCharsets.UTF_8), value),
                Hex.decode("c19fccf57c613f1868dd22d586f9571cf6412cd0"));
    }
}
