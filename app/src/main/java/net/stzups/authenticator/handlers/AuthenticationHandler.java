package net.stzups.authenticator.handlers;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import net.stzups.netty.http.HttpUtils;
import net.stzups.netty.http.exception.HttpException;
import net.stzups.netty.http.exception.exceptions.UnauthorizedException;
import net.stzups.netty.http.handler.HttpHandler;

import java.util.Set;

public class AuthenticationHandler extends HttpHandler {
    public AuthenticationHandler() {
        super("/authenticate");
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request, HttpResponse response) throws HttpException {
        //todo verify that this is actually coming from the proxy
        //System.out.println(request.headers());
        String cookiesHeader = request.headers().get(HttpHeaderNames.COOKIE);
        if (cookiesHeader == null) {
            throw new UnauthorizedException("Missing cookies");

        }

        Set<Cookie> cookies = ServerCookieDecoder.STRICT.decode(cookiesHeader);
        for (Cookie cookie : cookies) {
            if (!cookie.name().equals(Authenticate.COOKIE_NAME)) {
                continue;
            }

            if (!cookie.value().equals("secret_password")) {
                throw new UnauthorizedException("wrong secret password");
            }

            response.setStatus(HttpResponseStatus.OK);
            HttpUtils.send(ctx, request, response);
            return true;
        }
        throw new UnauthorizedException("Missing " + Authenticate.COOKIE_NAME + " cookie");
    }
}
