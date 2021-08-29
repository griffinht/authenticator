package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.SessionCookie;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.handler.HttpHandler;

public class LogoutHandler extends HttpHandler {
    private final Database database;

    public LogoutHandler(Database database) {
        super("/logout");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) throws HttpException {
        SessionCookie sessionCookie = SessionCookie.removeSessionCookie(request);
        HttpUtils.send(ctx, request, null);
        if (sessionCookie != null) {

        }
        return false;
    }
}
