package net.stzups.authenticator.authentication;

import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.DefaultCookie;

import java.security.SecureRandom;

import static net.stzups.authenticator.authentication.SessionCookie.COOKIE_NAME;

public class Session {
    static final int tokenLength = 4 * 8;

    private static final SecureRandom secureRandom = new SecureRandom();

    public final long id = secureRandom.nextLong();
    public byte[] hash;

    public Cookie generate() {
        byte[] token = new byte[32];
        secureRandom.nextBytes(token);
        DefaultCookie cookie = new DefaultCookie(COOKIE_NAME, Base64.encode(token));

        hash = PasswordUtil.hash(token);

        return cookie;
    }


}
