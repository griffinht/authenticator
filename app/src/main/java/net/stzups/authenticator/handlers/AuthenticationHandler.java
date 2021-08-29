package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import net.stzups.authenticator.Session;
import net.stzups.authenticator.SessionCookie;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;
import net.stzups.netty.http.handler.HttpHandler;

import java.util.HashMap;
import java.util.Map;

public class AuthenticationHandler extends HttpHandler {
    private Map<Long, Session> sessions = new HashMap<>();

    public AuthenticationHandler() {
        super("/authenticate");
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request, HttpResponse response) throws HttpException {
        //todo verify that this is actually coming from the proxy
        //System.out.println(request.headers());
        SessionCookie sessionCookie = SessionCookie.getSessionCookie(request);
        if (sessionCookie == null) {
            throw new UnauthorizedException("Missing session cookie");
        }

        Session session = sessions.get(sessionCookie.id);
        byte[] hash;
        if (session == null) {
            System.err.println("bad id");
            hash = null;
        } else {
            System.err.println("good id");
            hash = session.hash;
        }

        if (!sessionCookie.verify(hash)) {
            throw new UnauthorizedException("Bad session");
        }

        FullHttpResponse r = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        return true;
    }
}
