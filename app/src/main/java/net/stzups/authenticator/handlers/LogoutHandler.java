package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.authentication.SessionCookie;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.handler.HttpHandler;

public class LogoutHandler extends HttpHandler {
    private final Database database;

    public LogoutHandler(Database database) {
        super("/api/logout");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) {
        HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.SEE_OTHER);
        SessionCookie sessionCookie = SessionCookie.removeSessionCookie(request, response);
        response.headers().set(HttpHeaderNames.LOCATION, LoginHandler.LOGIN_PAGE);
        HttpUtils.send(ctx, request, response);
        // do the heavy lifting after sending the response
        if (sessionCookie == null) {
            TestLog.getLogger(ctx).info("Tried to log out with no session cookie");
            return true;
        }

        Session session = database.getSession(sessionCookie.id);
        if (session == null) {
            TestLog.getLogger(ctx).info("Tried to log out with non existent session id");
            return true;
        }

        if (!Session.verify(session, sessionCookie)) {
            TestLog.getLogger(ctx).warning("Tried to expire session " + session + " but had bad authentication token");
            return true;
        }

        database.removeSession(session);
        TestLog.getLogger(ctx).info("Logged out and expired session " + session);
        return true;
    }
}
