package net.stzups.authenticator.authentication;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import net.stzups.authenticator.DeserializationException;

import java.nio.charset.StandardCharsets;

public class Base64 {
    public static String encode(byte[] bytes) {
        ByteBuf byteBuf = Unpooled.wrappedBuffer(bytes);
        String string = encode(byteBuf);
        byteBuf.release();
        return string;
    }

    public static String encode(ByteBuf byteBuf) {
        ByteBuf base64 = io.netty.handler.codec.base64.Base64.encode(byteBuf);
        String string = base64.toString(StandardCharsets.UTF_8);
        base64.release();
        return string;
    }

    public static ByteBuf decode(String string) throws DeserializationException {
        ByteBuf base64 = Unpooled.wrappedBuffer(string.getBytes(StandardCharsets.UTF_8));
        ByteBuf byteBuf;
        try {
            byteBuf = io.netty.handler.codec.base64.Base64.decode(base64);
        } catch (IllegalArgumentException e) {
            throw new DeserializationException(e);
        }
        base64.release();
        return byteBuf;
    }
}
