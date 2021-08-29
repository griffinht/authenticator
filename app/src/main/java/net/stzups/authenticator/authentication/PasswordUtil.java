package net.stzups.authenticator.authentication;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;
import java.util.Arrays;

public class PasswordUtil {
    private static final SecureRandom secureRandom = new SecureRandom();

    private static final int saltLength = 128 / 8;
    private static final int hashLength = 256 / 8;
    private static final int parallelism = 1;
    private static final int memory = 10 * 1024;
    private static final int iterations = 10;

    private static final byte[] DUMMY_SALT = new byte[saltLength];
    private static final byte[] DUMMY_PASSWORD = new byte[hashLength];

    public static byte[][] hash(byte[] password) {
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);
        return new byte[][]{ hash(password, salt), salt };
    }

    public static byte[] hash(byte[] _password, byte[] _salt) {
        byte[] salt = _salt != null ? _salt : DUMMY_SALT;
        byte[] password = _password != null ? _password : DUMMY_PASSWORD;

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(new Argon2Parameters
                .Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withParallelism(parallelism)
                .withMemoryAsKB(memory)
                .withIterations(iterations)
                .build());

        byte[] hash = new byte[hashLength];
        generator.generateBytes(password, hash);
        if (_password == null || _salt == null) {
            return null;
        }
        // might as well clear password because it should not be reused
        Arrays.fill(password, (byte) 0);
        return hash;
    }
}
