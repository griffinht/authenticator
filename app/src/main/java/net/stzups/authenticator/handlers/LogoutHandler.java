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
        super("/logout");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) {
        HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.SEE_OTHER);
        SessionCookie sessionCookie = SessionCookie.removeSessionCookie(request, response);
        response.headers().set(HttpHeaderNames.LOCATION, "/login/");
        HttpUtils.send(ctx, request, response);
        // do the heavy lifting after sending the response
        if (sessionCookie != null) {
            Session session = database.removeSession(sessionCookie);
            if (session != null) {
                TestLog.getLogger(ctx).info("Logged out and expired session " + session);
            }
            TestLog.getLogger(ctx).info("Logged out but did not expire session");
        }
        TestLog.getLogger(ctx).info("Tried to log out with no session cookie");
        return true;
    }
}
