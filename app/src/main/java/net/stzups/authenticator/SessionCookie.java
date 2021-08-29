package net.stzups.authenticator;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.ServerCookieDecoder;

import java.util.Arrays;
import java.util.Set;

public class SessionCookie {
    public static final String COOKIE_NAME = "session";
    private static final byte[] DUMMY = new byte[Session.tokenLength];

    public final long id;
    private final byte[] token = new byte[Session.tokenLength];

    public SessionCookie(Cookie cookie) {
        ByteBuf byteBuf = Base64.decode(cookie.value());
        id = byteBuf.readLong();
        byteBuf.readBytes(token);
        byteBuf.release();
    }

    public boolean verify(byte[] hash) {
        if (hash == null) {
            hash = DUMMY;
        }
        // always return false if dummy password
        return Arrays.equals(Password.hash(token), hash) && hash != DUMMY;
    }

    public static SessionCookie getSessionCookie(HttpRequest request) {
        String cookiesHeader = request.headers().get(HttpHeaderNames.COOKIE);
        if (cookiesHeader == null) {
            return null;
        }

        Set<Cookie> cookies = ServerCookieDecoder.STRICT.decode(cookiesHeader);
        for (Cookie cookie : cookies) {
            if (!cookie.name().equals(SessionCookie.COOKIE_NAME)) {
                continue;
            }

            return new SessionCookie(cookie);
        }

        return null;
    }
}
