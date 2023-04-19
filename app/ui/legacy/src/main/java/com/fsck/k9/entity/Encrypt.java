package com.fsck.k9.entity;


public class Encrypt {

    private String key;
    private String body;

    public Encrypt(String key, String body) {
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
