package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Login;
import net.stzups.authenticator.authentication.Session;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.BadRequestException;
import net.stzups.netty.http.exception.exceptions.MethodNotAllowedException;
import net.stzups.netty.http.handler.HttpHandler;
import net.stzups.netty.http.objects.Form;

import java.nio.charset.StandardCharsets;

public class LoginHandler extends HttpHandler {
    private static class LoginRequest {
        private final String username;
        private final byte[] password;
        private final boolean remember;

        LoginRequest(FullHttpRequest request) throws BadRequestException {
            Form form = new Form(request);
            username = form.getText("username");
            password = form.getText("password").getBytes(StandardCharsets.UTF_8);
            remember = form.getCheckbox("remember");
        }
    }

    private final Database database;

    public LoginHandler(Database database) {
        super("/api/login");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) throws HttpException {
        if (!request.method().equals(HttpMethod.POST)) {
            throw new MethodNotAllowedException(request.method(), HttpMethod.POST);
        }


        HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.SEE_OTHER);

        LoginRequest loginRequest = new LoginRequest(request);
        if (!Login.verify(database.getLogin(loginRequest.username), loginRequest.password)) {
            TestLog.getLogger(ctx).info("Bad login");
            response.headers().set(HttpHeaderNames.LOCATION, "/login/");
            HttpUtils.send(ctx, request, response);
            return true;
        }

        TestLog.getLogger(ctx).info("Good login");

        if (loginRequest.remember) {
            TestLog.getLogger(ctx).info("Remember");
            //todo
        }

        Session session = createSession(response);
        response.headers().set(HttpHeaderNames.LOCATION, "/");
        HttpUtils.send(ctx, request, response);

        database.addSession(session);

        return true;
    }

    private static Session createSession(HttpResponse response) {
        Session session = new Session();
        response.headers().set(HttpHeaderNames.SET_COOKIE, ServerCookieEncoder.STRICT.encode(session.generate()));
        return session;
    }
}
