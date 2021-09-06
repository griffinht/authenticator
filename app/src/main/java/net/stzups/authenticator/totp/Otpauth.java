package net.stzups.authenticator.totp;

import org.bouncycastle.util.encoders.Base32;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class Otpauth {
    public enum Type {
        HOTP("hotp"),
        TOTP("totp"),
        ;

        public final String string;

        Type(String string) {
            this.string = string;
        }
    }
    public enum Digits {
        SIX(6),
        EIGHT(8),
        ;

        public final int digits;

        Digits(int digits) {
            this.digits = digits;
        }
    }

    enum Algorithm {
        SHA1("SHA1"),
        SHA256("SHA256"),
        SHA512("SHA512"),
        ;

        public final String string;

        Algorithm(String string) {
            this.string = string;
        }
    }

    /**
     * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
     */
    public static String getUri(Type type, String label, byte[] secret, String issuer, Digits digits, Algorithm algorithm, int counter, int period) {
        String base = "otpauth://" + type.string + "/" + label;

        Map<String, String> params = new HashMap<>();
        params.put("secret", new String(Base32.encode(secret), StandardCharsets.UTF_8));
        params.put("issuer", issuer);
        params.put("digits", "" + digits.digits);
        params.put("algorithm", algorithm.string);
        params.put("counter", "" + counter);
        params.put("period", "" + period);

        StringBuilder query = new StringBuilder("?");
        for (Map.Entry<String, String> param : params.entrySet()) {
            if (query.isEmpty()) query.append("?");
            else query.append("&");

            query.append(param.getKey()).append("=").append(param.getValue());
        }

        System.err.println(base + query);
        return base + query;
    }
}
