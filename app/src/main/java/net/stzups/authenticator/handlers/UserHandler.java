package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import net.stzups.authenticator.authentication.Database;
import net.stzups.authenticator.authentication.Session;
import net.stzups.authenticator.totp.TOTPGenerator;
import net.stzups.netty.TestLog;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.NotFoundException;
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

//todo what if totp is removed while someone is authenticating with totp?
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        if (request.method().equals(HttpMethod.GET)) {
            if (database.hasTotp(session.sessionInfo.user)) {
                throw new UnauthorizedException("User already has otp enabled");
            }

            byte[] secret = TOTPGenerator.generateSecret();
            database.setTotp(session.sessionInfo.user, secret);
            response.content().writeBytes(TOTPGenerator.getUri(secret, "server:johnny", "google.com").getBytes(StandardCharsets.UTF_8));



            //todo
            response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
            boolean keepAlive = HttpUtils.setKeepAlive(request, response);

            //ctx.write(response);
            //ChannelFuture flushPromise = ctx.writeAndFlush(content);
            ChannelFuture flushPromise = ctx.writeAndFlush(response);

            if (!keepAlive) {
                flushPromise.addListener(ChannelFutureListener.CLOSE);
            }
            //HttpUtils.send(ctx, request, response);




            TestLog.getLogger(ctx).info("Created totp for user");
        } else if (request.method().equals(HttpMethod.DELETE) || request.uri().endsWith("TEST_DELETE")) { //temp workaround
            database.removeTotp(session.sessionInfo.user);
            HttpUtils.send(ctx, request, response);
            TestLog.getLogger(ctx).info("Removed totp from user");
        } else {
            throw new NotFoundException("unknown method");
        }

        return true;
    }
}
