package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.handler.HttpHandler;

public class LoginHandler extends HttpHandler {
    public LoginHandler() {
        super("/login");
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request, HttpResponse r) throws HttpException {
        HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        Cookie cookie = new DefaultCookie(AuthenticationHandler.COOKIE_NAME, "secret_password");
        response.headers().set(HttpHeaderNames.SET_COOKIE, ServerCookieEncoder.STRICT.encode(cookie));
        HttpUtils.send(ctx, request, response);
        return true;
    }
}
