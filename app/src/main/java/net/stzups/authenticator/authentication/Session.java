package net.stzups.authenticator.authentication;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;
import net.stzups.authenticator.DeserializationException;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Session {
    static final int tokenLength = 128 / 8;

    private static final SecureRandom secureRandom = new SecureRandom();

    public final long id;
    private final byte[] hash;

    public Session(HttpResponse response) {
        id = secureRandom.nextLong();

        byte[] token = new byte[tokenLength];
        secureRandom.nextBytes(token);
        Cookie cookie = SessionCookie.createSessionCookie(id, token);
        response.headers().add(HttpHeaderNames.SET_COOKIE, ServerCookieEncoder.STRICT.encode(cookie));
        hash = hash(token);
    }

    public static boolean verify(Session session, byte[] token) {
        return Arrays.equals(hash(token), session != null ? session.hash : null);
    }

    private static byte[] hash(byte[] token) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Exception while getting algorithm SHA-256", e);
        }
        byte[] hash = messageDigest.digest(token);
        // might as well clear token because it should not be reused
        Arrays.fill(token, (byte) 0);
        return hash;
    }

    public static Session getSession(ChannelHandlerContext ctx, FullHttpRequest request, Database database) throws HttpException {
        SessionCookie sessionCookie;
        try {
            sessionCookie = SessionCookie.getSessionCookie(request);
        } catch (DeserializationException e) {
            // remove malformed session cookie
            HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED);
            SessionCookie.removeSessionCookie(request, response);
            HttpUtils.send(ctx, request, response);
            return null;
        }

        if (sessionCookie == null) {
            throw new UnauthorizedException("Missing session cookie");
        }

        Session session = database.getSession(sessionCookie.id);
        if (!Session.verify(session, sessionCookie.token)) {
            throw new UnauthorizedException("Bad session");
        }

        TestLog.getLogger(ctx).info("Good session");

        return session;
    }
}
