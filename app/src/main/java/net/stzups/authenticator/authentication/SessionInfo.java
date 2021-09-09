package net.stzups.authenticator.authentication;

import io.netty.buffer.ByteBuf;

import java.io.Serializable;

public class SessionInfo implements Serializable {
    public final long user;
    private boolean needsOtp;

    public SessionInfo(ByteBuf byteBuf) {
        user = byteBuf.readLong();
        needsOtp = byteBuf.readBoolean();
    }

    public SessionInfo(long user, boolean needsOtp) {
        this.user = user;
        this.needsOtp = needsOtp;
    }

    public boolean needsOtp() {
        return needsOtp;
    }

    public void finishOtp() {
        needsOtp = false;
    }

    public boolean canViewPrivate() {
        return !needsOtp;
    }
}
