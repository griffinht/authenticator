package net.stzups.authenticator.authentication;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;
import net.stzups.authenticator.DeserializationException;

import java.util.Set;

public class SessionCookie {
    public static final String COOKIE_NAME = "session";

    public final long id;
    public final byte[] token = new byte[Session.tokenLength];

    public SessionCookie(Cookie cookie) throws DeserializationException {
        ByteBuf byteBuf = Base64.decode(cookie.value());
        try {
            id = byteBuf.readLong();
            byteBuf.readBytes(token);
        } catch (IndexOutOfBoundsException e) {
            throw new DeserializationException(e);
        } finally {
            byteBuf.release();
        }
    }

    private static DefaultCookie createCookie(String value) {
        DefaultCookie cookie = new DefaultCookie(COOKIE_NAME, value);
        cookie.setPath("/");
        return cookie;
    }

    public static Cookie createSessionCookie(long id, byte[] token) {
        ByteBuf byteBuf = Unpooled.buffer();
        byteBuf.writeLong(id);
        byteBuf.writeBytes(token);
        DefaultCookie cookie = createCookie(Base64.encode(byteBuf));
        byteBuf.release();

        return cookie;
    }

    public static SessionCookie getSessionCookie(HttpRequest request) throws DeserializationException {
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

    public static SessionCookie removeSessionCookie(HttpRequest request, HttpResponse response) {
        SessionCookie sessionCookie;
        try {
            sessionCookie = getSessionCookie(request);
        } catch (DeserializationException e) {
            e.printStackTrace();
            return null;
        }

        //if (sessionCookie == null) return null; might as well always clear the cookie, even if nothing was found

        DefaultCookie cookie = createCookie("");
        cookie.setMaxAge(0);
        response.headers().add(HttpHeaderNames.SET_COOKIE, ServerCookieEncoder.STRICT.encode(cookie));

        return sessionCookie;
    }
}
