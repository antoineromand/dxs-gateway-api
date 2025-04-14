package com.dxs.gateway.dxs_gateway_api.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

@Service
public class TokenManager {

    public TokenManager() {}

    public Token getDecodedToken(String token) {
        JwtParser parser = Jwts.parser().build();
        Jwt<?, ?> parsedJwt = parser.parse(token);
        Claims claims = (Claims) parsedJwt.getPayload();
        return new Token(claims.getSubject(), claims.get("role", String.class));
    }
}
