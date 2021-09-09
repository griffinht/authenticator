package net.stzups.authenticator.database;

import net.stzups.authenticator.User;
import net.stzups.authenticator.authentication.Login;
import net.stzups.authenticator.authentication.Session;

public interface Database extends AutoCloseable {
    Session getSession(long id);
    void addSession(Session session);
    void removeSession(Session session);
    void addUser(User user);
    User getUser(long id);
    void addLogin(String username, Login login);
    Login getLogin(String username);
    void setTotp(long user, byte[] secret);
    void addTotp(long user, byte[] secret);
    boolean hasTotp(long user);
    byte[] getTotp(long user);
    void removeTotp(long user);
}
