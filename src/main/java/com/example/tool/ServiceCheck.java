package com.example.tool;

public class ServiceCheck {
    @FunctionalInterface
    public interface Checker {
        CheckOutcome check(TargetInfo targetInfo, int timeoutMillis);
    }

    private final String key;
    private final String displayName;
    private final int defaultPort;
    private final Checker checker;

    public ServiceCheck(String key, String displayName, int defaultPort, Checker checker) {
        this.key = key;
        this.displayName = displayName;
        this.defaultPort = defaultPort;
        this.checker = checker;
    }

    public String getKey() {
        return key;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getDefaultPort() {
        return defaultPort;
    }

    public Checker getChecker() {
        return checker;
    }
}
