package com.workers.wsgateway.config.filter;

import lombok.SneakyThrows;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static com.workers.wsgateway.config.security.util.Constant.AUTH_TOKEN_PREFIX;
import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.getHeaderRequest;
import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.getUsername;

@Component
public class AddUserIdHeaderFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String userId = extractUserIdFromToken(exchange.getRequest());

        if (userId != null) {
            ServerHttpRequest request = exchange.getRequest().mutate()
                    .header("X-User-Id", userId)
                    .build();
            exchange = exchange.mutate().request(request).build();
        }

        return chain.filter(exchange);
    }

    @SneakyThrows
    private String extractUserIdFromToken(ServerHttpRequest request) {
        String header = getHeaderRequest(request);
        if (header != null
                && header.startsWith(AUTH_TOKEN_PREFIX)) {
            return getUsername(header).getSub();
        }
        return null;
    }
}
