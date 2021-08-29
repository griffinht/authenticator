package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;
import net.stzups.authenticator.authentication.Session;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.BadRequestException;
import net.stzups.netty.http.exception.exceptions.MethodNotAllowedException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;
import net.stzups.netty.http.handler.HttpHandler;
import net.stzups.netty.http.objects.Form;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class LoginHandler extends HttpHandler {
    private static class LoginRequest {
        private final String username;
        private final String password;
        private final boolean remember;

        LoginRequest(FullHttpRequest request) throws BadRequestException {
            Form form = new Form(request);
            username = form.getText("username");
            password = form.getText("password");
            remember = form.getCheckbox("remember");
        }
    }

    private Map<Long, Session> sessions = new HashMap<>();
    private Map<Long, byte[]> remember = new HashMap<>();

    public LoginHandler() {
        super("/login");
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request, HttpResponse r) throws HttpException {
        if (!request.method().equals(HttpMethod.POST)) {
            throw new MethodNotAllowedException(request.method(), HttpMethod.POST);
        }

        LoginRequest loginRequest = new LoginRequest(request);
        if (!loginRequest.username.equals("user") || !loginRequest.password.equals("password")) {
            throw new UnauthorizedException("Bad username/password");
        }

        SecureRandom secureRandom = new SecureRandom();
        sessions.put(secureRandom.nextLong(), new Session());

        HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);

        Session session = createSession(response);
        sessions.put(session.id, session);

        HttpUtils.send(ctx, request, response);
        return true;
    }

    private static Session createSession(HttpResponse response) {
        Session session = new Session();
        response.headers().set(HttpHeaderNames.SET_COOKIE, ServerCookieEncoder.STRICT.encode(session.generate()));
        return session;
    }
}
