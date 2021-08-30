package net.stzups.authenticator.authentication;

import net.stzups.authenticator.User;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class Database {
    private Map<Long, Session> sessions = new HashMap<>();
    private Map<String, Login> logins = new HashMap<>();
    private Map<Long, User> users = new HashMap<>();

    public Database() {
        User user = new User("your mom");
        users.put(user.id, user);
        logins.put("admin", new Login("password".getBytes(StandardCharsets.UTF_8), user.id));
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

    public User getUser(long id) {
        return users.get(id);
    }

    public Login getLogin(String username) {
        return logins.get(username);
    }
}
