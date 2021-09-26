package net.stzups.authenticator.data;


import net.stzups.config.ConfigKey;
import net.stzups.config.OptionalConfigKey;
import net.stzups.config.configs.EnvironmentVariableConfig;
import net.stzups.config.configs.PropertiesConfig;

public class DefaultConfig extends net.stzups.config.Config implements Config {
    private static final ConfigKey<String> USERNAMES = new OptionalConfigKey<>("usernames", "");

    public DefaultConfig() {
        addConfigProvider(new PropertiesConfig("config.properties"));
        addConfigProvider(new EnvironmentVariableConfig("AUTHENTICATOR"));
    }

    @Override
    public String[] getUsernames() {
        return getString(USERNAMES).split(",");
    }
}
