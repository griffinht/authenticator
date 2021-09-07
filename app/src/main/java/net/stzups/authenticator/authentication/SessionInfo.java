package net.stzups.authenticator.authentication;

public class SessionInfo {
    public final long user;
    private boolean needsOtp = false;

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
