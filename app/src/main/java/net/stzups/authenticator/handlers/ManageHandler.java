package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Session;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;
import net.stzups.netty.http.handler.HttpHandler;

public class ManageHandler extends HttpHandler {
    private final Database database;

    protected ManageHandler(Database database) {
        super("/manage");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) throws HttpException {
        Session session = Session.getSession(ctx, request, database);
        if (session == null) {
            return true;
        }

        if (!session.canManage()) {
            throw new UnauthorizedException("Session " + session + " does not have manage permissions");
        }

        TestLog.getLogger(ctx).info("managing");
        //todo do stuff based on action like add/remove users
        return true;
    }
}
