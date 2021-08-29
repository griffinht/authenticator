package net.stzups.authenticator;

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
    private static final String COOKIE_NAME = "session";

    protected AuthenticationHandler() {
        super("/authenticator");
    }

    @Override
    public boolean handle(ChannelHandlerContext ctx, FullHttpRequest request, HttpResponse response) throws HttpException {
        //todo verify that this is actually coming from the proxy
        //System.out.println(request.headers());
        String cookiesHeader = request.headers().get(HttpHeaderNames.COOKIE);
        if (cookiesHeader == null) {
            throw new UnauthorizedException("Missing any cookie");

        }

        Set<Cookie> cookies = ServerCookieDecoder.STRICT.decode(cookiesHeader);
        for (Cookie cookie : cookies) {
            if (!cookie.name().equals(COOKIE_NAME)) {
                continue;
            }

            System.out.println(cookie.value());
            response.setStatus(HttpResponseStatus.OK);
            HttpUtils.send(ctx, request, response);
            return true;
        }
        throw new UnauthorizedException("Missing " + COOKIE_NAME + " cookie");
    }
}
