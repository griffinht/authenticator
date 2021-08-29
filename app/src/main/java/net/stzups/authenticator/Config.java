package net.stzups.authenticator;

import net.stzups.netty.http.HttpServerInitializer;

public class Config implements HttpServerInitializer.Config {
    @Override
    public boolean getSSL() {
        return false;
    }

    @Override
    public String getSSLRootPath() {
        return null;
    }

    @Override
    public String getSSLPath() {
        return null;
    }

    @Override
    public boolean getDebugLogTraffic() {
        return false;
    }
}
