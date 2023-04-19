package com.fsck.k9.entity;


public class Decrypt {
    private String key;
    private String body;

    public Decrypt(String key, String body) {
        this.key = key;
        this.body = body;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
}
