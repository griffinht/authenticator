package net.stzups.authenticator.database;

public class DatabaseException extends Exception {
    public DatabaseException(String string, Exception exception) {
        super(string, exception);
    }
}
