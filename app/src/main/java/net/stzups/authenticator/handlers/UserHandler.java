package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Session;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.NotFoundException;
import net.stzups.netty.http.handler.HttpHandler;

public class UserHandler extends HttpHandler {
    private final Database database;

    protected UserHandler(Database database) {
        super("/api/users");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) throws HttpException {
        Session session = Session.getSession(ctx, request, database);
        if (session == null) {
            return true;
        }


        if (request.method().equals(HttpMethod.GET)) {
            //todo return info about user
        } else if (request.method().equals(HttpMethod.POST)) {
            //todo add new user
        } else if (request.method().equals(HttpMethod.PUT)) {
            //todo update user
        } else if (request.method().equals(HttpMethod.DELETE)) {
            //todo delete user
        } else {
            throw new NotFoundException("Unknown method " + request.method());
        }

        TestLog.getLogger(ctx).info("managing");
        //todo do stuff based on action like add/remove users
        return true;
    }
}
