package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Login;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.authentication.SessionInfo;
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

    static final String LOGIN_PAGE = "/public/";  // page where login requests come from
    static final String LOGGED_IN_PAGE = "/"; // page where logged in users go
    static final String OTP_PAGE = "/public/otp.html"; // page where users who need to do otp go

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

        LoginRequest loginRequest = new LoginRequest(request); // always verify first and fail first before any time sensitive database stuff


        HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.SEE_OTHER);
        Login login = database.getLogin(loginRequest.username);
        if (!Login.verify(login, loginRequest.password)) {
            TestLog.getLogger(ctx).info("Bad login");
            response.headers().set(HttpHeaderNames.LOCATION, LOGIN_PAGE);
            HttpUtils.send(ctx, request, response);
            return true;
        }

        TestLog.getLogger(ctx).info("Good login");

        //todo check for 2fa

        Session session = new Session(response, loginRequest.remember, new SessionInfo(login.user, database.hasTotp(login.user)));
        response.headers().set(HttpHeaderNames.LOCATION, session.sessionInfo.needsOtp() ? OTP_PAGE : LOGGED_IN_PAGE);
        HttpUtils.send(ctx, request, response);

        database.addSession(session);

        return true;
    }

}
