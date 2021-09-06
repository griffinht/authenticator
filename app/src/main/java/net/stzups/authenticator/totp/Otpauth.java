package net.stzups.authenticator.totp;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.base64.Base64;

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

        public  final int digits;

        Digits(int digits) {
            this.digits = digits;
        }
    }

    private static String toBase64(byte[] value) {
        ByteBuf byteBuf = Unpooled.wrappedBuffer(value);
        ByteBuf base64 = Base64.encode(byteBuf);
        byteBuf.release();
        try {
            return base64.toString(StandardCharsets.UTF_8);
        } finally {
            base64.release();
        }
    }

    public static String getUri(Type type, String label, byte[] secret, String issuer, Digits digits, int counter, int period) {
        String base = "otpauth://" + type.string + "/" + label;

        Map<String, String> params = new HashMap<>();
        params.put("secret", toBase64(secret));
        //params.put("issuer", issuer);
        //params.put("digits", "" + digits.digits);
        //params.put("counter", "" + counter);
        //params.put("period", "" + period);

        StringBuilder query = new StringBuilder("?");
        for (Map.Entry<String, String> param : params.entrySet()) {
            if (query.isEmpty()) query.append("?");
            else query.append("&");

            query.append(param.getKey()).append("=").append(param.getValue());
        }

        return base + query;
    }
}
