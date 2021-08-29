package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import net.stzups.authenticator.DeserializationException;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.authentication.SessionCookie;
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
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request, HttpResponse response) throws HttpException {
        //todo verify that this is actually coming from the proxy
        //System.out.println(request.headers());
        SessionCookie sessionCookie;
        try {
             sessionCookie = SessionCookie.getSessionCookie(request);
        } catch (DeserializationException e) {
            throw new UnauthorizedException("malformed", e);
        }
        if (sessionCookie == null) {
            throw new UnauthorizedException("Missing session cookie");
        }

        if (!Session.verify(database.getSession(sessionCookie.id), sessionCookie.token)) {
            throw new UnauthorizedException("bad session");
        }

        System.err.println("good session");

        HttpUtils.send(ctx, request, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
        return true;
    }
}
