package com.example.tool;

public class ScanRecord {
    private final String target;
    private final String checkName;
    private final String status;
    private final String message;
    private final String time;

    public ScanRecord(String target, String checkName, String status, String message, String time) {
        this.target = target;
        this.checkName = checkName;
        this.status = status;
        this.message = message;
        this.time = time;
    }

    public String getTarget() {
        return target;
    }

    public String getCheckName() {
        return checkName;
    }

    public String getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public String getTime() {
        return time;
    }
}
