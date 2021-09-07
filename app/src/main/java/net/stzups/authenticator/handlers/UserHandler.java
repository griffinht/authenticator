package net.stzups.authenticator.handlers;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.totp.TOTPGenerator;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;
import net.stzups.netty.http.handler.HttpHandler;

import java.nio.charset.StandardCharsets;

public class UserHandler extends HttpHandler {
    private final Database database;

    public UserHandler(Database database) {
        super("/api/user/otp");
        this.database = database;
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request) throws HttpException {
        Session session = Session.getSession(ctx, request, database);
        if (session == null) {
            throw new UnauthorizedException("No session");
        }

        if (!session.sessionInfo.canViewPrivate()) {
            throw new UnauthorizedException("No permissions");
        }


        HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        if (request.method().equals(HttpMethod.GET)) {
            if (database.hasTotp(session.sessionInfo.user)) {
                throw new UnauthorizedException("User already has otp enabled");
            }

            byte[] secret = TOTPGenerator.generateSecret();
            database.setTotp(session.sessionInfo.user, secret);
            ByteBuf byteBuf = Unpooled.wrappedBuffer(TOTPGenerator.getUri(secret).getBytes(StandardCharsets.UTF_8));
            HttpUtils.send(ctx, request, response, byteBuf);
            byteBuf.release();
        } else if (request.method().equals(HttpMethod.DELETE)) {
            database.removeTotp(session.sessionInfo.user);
            HttpUtils.send(ctx, request, response);
        }

        return true;
    }
}
