package com.dxs.gateway.dxs_gateway_api.jwt;

public class Token {
    private String id;
    private String role;

    public Token(String id, String role) {
        this.id = id;
        this.role = role;
    }

    public String getId() {
        return id;
    }

    public String getRole() {
        return role;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
