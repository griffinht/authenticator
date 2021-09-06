package net.stzups.authenticator.totp;

// this might break because of y38
public class TOTP {
    private static final long T0 = 0;
    private static long unixTime() {
        return System.currentTimeMillis() / 1000L;
    }
    private static final int TIME_STEP = 30;

    private static long t(long unixTime, long t0, int timeStep) {
        return (unixTime - t0) / timeStep;
    }

    private static void generate() {
        long t = t(unixTime(), T0, TIME_STEP);
        Object totp = HOTP.HOTP(null, t);
    }

}
