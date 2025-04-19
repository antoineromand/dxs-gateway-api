package com.dxs.gateway.dxs_gateway_api.jwt;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class JwtDecoder {

    public JwtDecoder() {}

    public Token decodeToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Format JWT invalide");
            }

            String payloadJson = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));

            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> payload = mapper.readValue(payloadJson, new TypeReference<Map<String, Object>>() {});

            String id = (String) payload.get("sub");
            String role = (String) payload.get("role");

            if (id == null || role == null) {
                throw new IllegalArgumentException("Claims manquants : sub ou role");
            }

            return new Token(id, role);
        } catch (Exception e) {
            throw new RuntimeException("Échec du décodage JWT : " + e.getMessage());
        }
    }
}
