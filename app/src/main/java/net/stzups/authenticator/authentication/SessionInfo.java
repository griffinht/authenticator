package net.stzups.authenticator.authentication;

import java.io.Serializable;

public class SessionInfo implements Serializable {
    public final long user;
    private boolean needsOtp;

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
