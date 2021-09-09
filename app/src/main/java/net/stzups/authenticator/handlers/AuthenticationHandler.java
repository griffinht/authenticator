package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.database.Database;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;
import net.stzups.netty.http.handler.HttpHandler;

public class AuthenticationHandler extends HttpHandler {
    private final Database database;

    public AuthenticationHandler(Database database) {
        super("/api/authenticate");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) throws HttpException {
        //todo verify that this is actually coming from the proxy
        //System.err.println(request.headers());
        Session session = Session.getSession(ctx, request, database);
        if (session == null) {
            throw new UnauthorizedException("Bad session");
        }

        if (!session.sessionInfo.canViewPrivate()) {
            throw new UnauthorizedException("No permission to view private");
        }

        HttpUtils.send(ctx, request, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
        return true;
    }
}
