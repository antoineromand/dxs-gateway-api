package com.dxs.gateway.dxs_gateway_api.filter;

import com.dxs.gateway.dxs_gateway_api.jwt.JwtDecoder;
import com.dxs.gateway.dxs_gateway_api.jwt.Token;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import java.util.Objects;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final WebClient webClient;
    private final JwtDecoder jwtDecoder;

    @Value("${gateway.api.key}")
    private String apiKey;

    public AuthenticationFilter(WebClient.Builder webClientBuilder, JwtDecoder jwtDecoder) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            try {
                String jwt = Objects.requireNonNull(exchange.getRequest().getCookies().getFirst("dxs-cookie-token")).getValue();
                return webClient.get()
                        .uri(config.getAuthenticationUri())
                        .cookie("dxs-cookie-token", jwt)
                        .exchangeToMono(clientResponse -> {
                            if (clientResponse.statusCode().equals(HttpStatus.UNAUTHORIZED)) {
                                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                return exchange.getResponse().setComplete();
                            }
                            try {
                                Token decodedToken = this.jwtDecoder.decodeToken(jwt);
                                ServerWebExchange mutatedExchange = exchange.mutate()
                                        .request(exchange.getRequest().mutate()
                                                .header("X-User-Id", decodedToken.getId())
                                                .header("X-User-Role", decodedToken.getRole())
                                                .header("X-Api-Key", this.apiKey)
                                                .build())
                                        .build();
                                return chain.filter(mutatedExchange);
                            } catch (Exception e) {
                                System.err.println("Error while decoding payload : " + e.getMessage());
                                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                return exchange.getResponse().setComplete();
                            }
                        })
                        .onErrorResume(e -> {
                            System.err.println("Invalid token : " + e.getMessage());
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        });
            } catch (NullPointerException e) {
                System.err.println("Error while getting token from cookie : cookie token is " + e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        };
    }

    public static class Config {
        private String authenticationUri;

        public String getAuthenticationUri() {
            return authenticationUri;
        }

        public void setAuthenticationUri(String authenticationUri) {
            this.authenticationUri = authenticationUri;
        }
    }
}
