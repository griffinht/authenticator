package net.stzups.authenticator.authentication;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;
import java.util.Arrays;

public class PasswordUtil {
    private static final SecureRandom secureRandom = new SecureRandom();

/*    static final int SALT_LENGTH = 128 / 8;
    static final int HASH_LENGTH = 256 / 8;
    private static final int PARALLELISM = 1;
    private static final int MEMORY = 10 * 1024;
    private static final int ITERATIONS = 10;*/

    static final int SALT_LENGTH = 128 / 8;
    static final int HASH_LENGTH = 256 / 8;
    private static final int PARALLELISM = 1;
    private static final int MEMORY = 2;
    private static final int ITERATIONS = 1;
    private static final byte[] DUMMY_SALT = new byte[SALT_LENGTH];
    private static final byte[] DUMMY_PASSWORD = new byte[HASH_LENGTH];

    public static byte[][] hash(byte[] password) {
        byte[] salt = new byte[SALT_LENGTH];
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
                .withParallelism(PARALLELISM)
                .withMemoryAsKB(MEMORY)
                .withIterations(ITERATIONS)
                .build());

        byte[] hash = new byte[HASH_LENGTH];
        generator.generateBytes(password, hash);
        if (_password != null) {
            // might as well clear password because it should not be reused
            Arrays.fill(_password, (byte) 0);
        }
        return hash;
    }
}
