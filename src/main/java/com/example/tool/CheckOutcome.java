package com.example.tool;

public class CheckOutcome {
    private final boolean vulnerable;
    private final String message;

    public CheckOutcome(boolean vulnerable, String message) {
        this.vulnerable = vulnerable;
        this.message = message;
    }

    public boolean isVulnerable() {
        return vulnerable;
    }

    public String getMessage() {
        return message;
    }
}
