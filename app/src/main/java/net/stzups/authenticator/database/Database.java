package net.stzups.authenticator.database;

import net.stzups.authenticator.User;
import net.stzups.authenticator.authentication.Login;
import net.stzups.authenticator.authentication.Session;

public interface Database extends AutoCloseable {
    Session getSession(long id) throws DatabaseException;
    void addSession(Session session) throws DatabaseException;
    void removeSession(Session session) throws DatabaseException;
    void addUser(User user) throws DatabaseException;
    User getUser(long id) throws DatabaseException;
    void addLogin(String username, Login login) throws DatabaseException;
    Login getLogin(String username) throws DatabaseException;
    void setTotp(long user, byte[] secret) throws DatabaseException;
    void addTotp(long user, byte[] secret) throws DatabaseException;
    boolean hasTotp(long user) throws DatabaseException;
    byte[] getTotp(long user) throws DatabaseException;
    void removeTotp(long user) throws DatabaseException;
}
