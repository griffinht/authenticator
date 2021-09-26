package net.stzups.authenticator;

import io.netty.channel.ChannelFuture;
import net.stzups.authenticator.authentication.Login;
import net.stzups.authenticator.data.Config;
import net.stzups.authenticator.data.Database;
import net.stzups.authenticator.data.DefaultConfig;
import net.stzups.authenticator.data.FileDatabase;
import net.stzups.netty.Server;

import java.nio.charset.StandardCharsets;

public class Authenticator {

    public static void main(String[] args) throws Exception {
        System.err.println("Starting server...");

        Config config = new DefaultConfig();

        try (Server server = new Server(8080);
             Database database = FileDatabase.getFileDatabase()) {
            Runtime.getRuntime().addShutdownHook(new Thread(server::close));

            ChannelFuture closeFuture = server.start(new HttpServerInitializer(new net.stzups.netty.http.HttpServerInitializer.Config() {
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
                }, database));

            for (String username : config.getUsernames()) {
                if (database.getLogin(username) != null) continue;

                User user = new User(username);
                database.addUser(user);
                String password = "password";
                Login login = new Login(password.getBytes(StandardCharsets.UTF_8), user.id);
                database.addLogin(username, login);
                System.err.println("Created user " + user + " with the following login:\nUsername:\n" + username + "\nPassword:\n" + password + "\nMake sure to reset this to a stronger password.");//todo force reset
            }

            System.err.println("Started server");
            closeFuture.sync();
            System.err.println("Stopping server...");


            System.err.println("Server stopped");
        }
    }

}
