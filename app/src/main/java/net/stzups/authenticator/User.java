package net.stzups.authenticator;

import java.security.SecureRandom;

public class User {
    private static final SecureRandom secureRandom = new SecureRandom();

    public final long id;
    public final String name;

    public User(String name) {
        this.id = secureRandom.nextLong();
        this.name = name;
    }
}
