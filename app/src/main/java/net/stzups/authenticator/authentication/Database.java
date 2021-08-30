package net.stzups.authenticator.authentication;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class Database {
    private Map<Long, Session> sessions = new HashMap<>();
    private Map<String, Login> logins = new HashMap<>();

    public Database() {
        addLogin("admin", new Login("password".getBytes(StandardCharsets.UTF_8)));
    }

    public Session getSession(long id) {
        return sessions.get(id);
    }

    public void addSession(Session session) {
        sessions.put(session.id, session);
    }

    public void removeSession(Session session) {
       sessions.remove(session.id);
    }

    public Login getLogin(String username) {
        return logins.get(username);
    }

    public void addLogin(String username, Login login) {
        logins.put(username, login);
    }

    public void removeLogin(String username) {
        //todo verify before removal with password?
        logins.remove(username);
    }
}
