package net.stzups.authenticator;

import io.netty.buffer.ByteBuf;
import net.stzups.netty.util.NettyUtils;

import java.io.Serializable;
import java.security.SecureRandom;

public class User implements Serializable {
    private static final SecureRandom secureRandom = new SecureRandom();

    public final long id;
    public final String name;

    public User(ByteBuf byteBuf) {
        id = byteBuf.readLong();
        name = NettyUtils.readString8(byteBuf);
    }

    public void serialize(ByteBuf byteBuf) {
        byteBuf.writeLong(id);
        NettyUtils.writeString8(byteBuf, name);
    }

    public User(String name) {
        this.id = secureRandom.nextLong();
        this.name = name;
    }
}
