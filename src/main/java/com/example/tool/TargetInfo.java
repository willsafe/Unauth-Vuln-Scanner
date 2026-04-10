package com.example.tool;

public class TargetInfo {
    private final String input;
    private final String host;
    private final Integer port;

    public TargetInfo(String input, String host, Integer port) {
        this.input = input;
        this.host = host;
        this.port = port;
    }

    public String getInput() {
        return input;
    }

    public String getHost() {
        return host;
    }

    public Integer getPort() {
        return port;
    }

    public int getPortOrDefault(int defaultPort) {
        return port == null ? defaultPort : port;
    }
}
