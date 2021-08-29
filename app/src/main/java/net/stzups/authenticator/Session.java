package net.stzups.authenticator;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.base64.Base64;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class Session {
    private static final String COOKIE_NAME = "session";

    private static final SecureRandom secureRandom = new SecureRandom();

    public final long id = secureRandom.nextLong();
    public byte[] hashed;

    public Cookie generate() {
        byte[] token = new byte[32];
        secureRandom.nextBytes(token);
        ByteBuf tokenBuffer = Unpooled.wrappedBuffer(token);
        ByteBuf tokenBase64 = Base64.encode(tokenBuffer);
        tokenBuffer.release();
        DefaultCookie cookie = new DefaultCookie(COOKIE_NAME, tokenBase64.toString(StandardCharsets.UTF_8));
        tokenBase64.release();

        hashed = hash(token);

        return cookie;
    }

    private static byte[] hash(byte[] token) {
        int saltLength = 128 / 8;
        int hashLength = 256 / 8;
        int parallelism = 1;
        int memory = 10 * 1024;
        int iterations = 10;

        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(new Argon2Parameters
                .Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withParallelism(parallelism)
                .withMemoryAsKB(memory)
                .withIterations(iterations)
                .build());

        byte[] hash = new byte[hashLength];
        generator.generateBytes(token, hash);
        // might as well since the token shouldn't be reused
        Arrays.fill(token, (byte) 0);
        return hash;
    }
}
