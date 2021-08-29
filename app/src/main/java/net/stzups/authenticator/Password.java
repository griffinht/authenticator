package net.stzups.authenticator;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;
import java.util.Arrays;

public class Password {
    private static final SecureRandom secureRandom = new SecureRandom();

    private static final int saltLength = 128 / 8;
    private static final int hashLength = 256 / 8;
    private static final int parallelism = 1;
    private static final int memory = 10 * 1024;
    private static final int iterations = 10;

    public static byte[] hash(byte[] token) {
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
