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
     * https://www.twilio.com/docs/verify/quickstarts/totp#create-a-qr-code
     * authy seems to work with digits 4-8
     * example: otpauth://totp/Twilio:John%E2%80%99s%20Account%20Name?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Twilio&algorithm=SHA1&digits=6&period=30
     */
    public static String getUri(Type type, String label, byte[] secret, String issuer, int digits, Algorithm algorithm, Integer counter, Integer period) {
        String base = "otpauth://" + type.string + "/" + label;

        Map<String, String> params = new HashMap<>();
        params.put("secret", new String(Base32.encode(secret), StandardCharsets.UTF_8));
        params.put("issuer", issuer);
        params.put("digits", "" + digits);
        params.put("algorithm", algorithm.string);
        if (counter != null) params.put("counter", "" + counter);
        if (period != null) params.put("period", "" + period);

        StringBuilder query = new StringBuilder("?");
        for (Map.Entry<String, String> param : params.entrySet()) {
            if (query.isEmpty()) query.append("?");
            else query.append("&");

            query.append(param.getKey()).append("=").append(param.getValue());
        }

        return base + query;
    }
}
