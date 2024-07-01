package com.workers.wsgateway.config.security.context;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Data
@RequiredArgsConstructor
public class AuthenticationFilterWebFluxContext {

    private final ServerWebExchange exchange;
    private final WebFilterChain chain;

    public Mono<Void> filter() {
        return chain.filter(exchange);
    }
}
