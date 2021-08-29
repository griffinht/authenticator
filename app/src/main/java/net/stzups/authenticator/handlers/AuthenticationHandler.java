package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import net.stzups.authenticator.DeserializationException;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.authentication.SessionCookie;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;
import net.stzups.netty.http.handler.HttpHandler;

public class AuthenticationHandler extends HttpHandler {
    private final Database database;

    public AuthenticationHandler(Database database) {
        super("/authenticate");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) throws HttpException {
        //todo verify that this is actually coming from the proxy
        //System.err.println(request.headers());
        SessionCookie sessionCookie;
        try {
             sessionCookie = SessionCookie.getSessionCookie(request);
        } catch (DeserializationException e) {
            throw new UnauthorizedException("Exception while deserializing session cookie", e);
        }
        if (sessionCookie == null) {
            throw new UnauthorizedException("Missing session cookie");
        }

        if (!Session.verify(database.getSession(sessionCookie.id), sessionCookie.token)) {
            throw new UnauthorizedException("Bad session");
        }

        TestLog.getLogger(ctx).info("Good session");

        HttpUtils.send(ctx, request, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
        return true;
    }
}
