package com.dxs.gateway.dxs_gateway_api.filter;

import com.dxs.gateway.dxs_gateway_api.jwt.Token;
import com.dxs.gateway.dxs_gateway_api.jwt.TokenManager;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Objects;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final WebClient webClient;
    private final TokenManager tokenManager;

    public AuthenticationFilter(WebClient.Builder webClientBuilder, TokenManager tokenManager) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
        this.tokenManager = tokenManager;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String jwt = Objects.requireNonNull(exchange.getRequest().getCookies().getFirst("dxs-cookie-token")).getValue();
            try {
                return webClient.get()
                        .uri(config.getAuthenticationUri())
                        .cookie("dxs-cookie-token", jwt)
                        .exchangeToMono(clientResponse -> {
                            if (clientResponse.statusCode().equals(HttpStatus.UNAUTHORIZED)) {
                                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                return exchange.getResponse().setComplete();
                            }
                            try {
                                Token decodedToken = this.tokenManager.getDecodedToken(jwt);
                                System.out.println(decodedToken.getId() + " // " + decodedToken.getRole());
                                exchange.getResponse().setStatusCode(HttpStatus.OK);
                                return exchange.getResponse().setComplete();
                            } catch (Exception e) {
                                System.err.println("Error : " + e.getMessage());
                                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                return exchange.getResponse().setComplete();
                            }
                        })
                        .onErrorResume(e -> {
                            System.err.println("Error while verify token : " + e.getMessage());
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        });
            } catch (Exception e) {
                System.err.println("Error while getting token from cookie : " + e.getMessage());
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
