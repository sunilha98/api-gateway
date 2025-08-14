package com.resourcemanagement.gateway.config;

import com.resourcemanagement.gateway.blacklisteds.service.BlacklistedTokenService;
import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final JwtTokenUtil jwtTokenUtil;
    private final BlacklistedTokenService blacklistedTokenService;

    public JwtAuthenticationFilter(JwtTokenUtil jwtTokenUtil, BlacklistedTokenService blacklistedTokenService) {
        super(Config.class);
        this.jwtTokenUtil = jwtTokenUtil;
        this.blacklistedTokenService = blacklistedTokenService;
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

            if (blacklistedTokenService.isBlacklisted(token)) {
                return this.onError(response, HttpStatus.UNAUTHORIZED, "Token has been blacklisted");
            }

            if (!jwtTokenUtil.validateToken(token)) {
                return this.onError(response, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
            }

            Claims claims = jwtTokenUtil.getAllClaimsFromToken(token);
            String username = claims.getSubject();
            String email = (String) claims.get("email");
            String role = claims.get("role").toString();

            ServerHttpRequest modifiedRequest = request.mutate().header("X-Auth-Username", username)
                    .header("X-Auth-Email", email).header("X-Auth-Role", role)
                    .header("X-Bearer-Token", token).build();

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