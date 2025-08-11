package com.resourcemanagement.gateway.config;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final JwtTokenUtil jwtTokenUtil;

    public JwtAuthenticationFilter(JwtTokenUtil jwtTokenUtil) {
        super(Config.class);
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return this.onError(response, HttpStatus.UNAUTHORIZED, "Missing authorization header");
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            String token = authHeader.replace("Bearer ", "");

            if (!jwtTokenUtil.validateToken(token)) {
                return this.onError(response, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
            }

            Claims claims = jwtTokenUtil.getAllClaimsFromToken(token);
            String username = claims.getSubject();
            String email = (String) claims.get("email");
            String role = (String) claims.get("role").toString();

            ServerHttpRequest modifiedRequest = request.mutate().header("X-Auth-Username", username)
                    .header("X-Auth-Email", email).header("X-Auth-Role", role).build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private Mono<Void> onError(ServerHttpResponse response, HttpStatus httpStatus, String errorMessage) {
        response.setStatusCode(httpStatus);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        return response.setComplete();
    }

    public static class Config {
    }
}