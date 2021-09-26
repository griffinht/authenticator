package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.data.Database;
import net.stzups.authenticator.totp.TOTPGenerator;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.BadRequestException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;
import net.stzups.netty.http.handler.HttpHandler;
import net.stzups.netty.http.objects.Form;

public class OtpHandler extends HttpHandler {
    private static class OtpRequest {
        private final int code;

        private OtpRequest(FullHttpRequest request) throws BadRequestException {
            Form form = new Form(request);
            String code = form.getText("otp");
            try {
                this.code = Integer.parseInt(code);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Exception while parsing " + code + " as integer for code", e);
            }
        }
    }
    private final Database database;

    public OtpHandler(Database database) {
        super("/api/otp");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) throws HttpException {
        OtpRequest otpRequest = new OtpRequest(request);

        Session session = Session.getSession(ctx, request, database);
        if (session == null) {
            throw new UnauthorizedException("Bad session");
        }

        HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.SEE_OTHER);
        if (!session.sessionInfo.needsOtp()) {
            response.headers().set(HttpHeaderNames.LOCATION, LoginHandler.LOGIN_PAGE);
            HttpUtils.send(ctx, request, response);
            TestLog.getLogger(ctx).info("Otp not required, redirecting...");
            return true;

        }

        if (!TOTPGenerator.verify(database.getTotp(session.sessionInfo.user), otpRequest.code)) {
            response.headers().set(HttpHeaderNames.LOCATION, LoginHandler.OTP_PAGE);
            HttpUtils.send(ctx, request, response);
            TestLog.getLogger(ctx).info("Bad otp, redirecting...");
            return true;
        }

        session.sessionInfo.finishOtp();
        response.headers().set(HttpHeaderNames.LOCATION, LoginHandler.LOGGED_IN_PAGE);
        HttpUtils.send(ctx, request, response);
        TestLog.getLogger(ctx).info("Good otp");
        return true;
    }
}
