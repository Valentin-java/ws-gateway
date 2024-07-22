package com.workers.wsgateway.config.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalErrorHandlingFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange).onErrorResume(error -> {
            if (error instanceof ResponseStatusException) {
                ResponseStatusException ex = (ResponseStatusException) error;
                exchange.getResponse().setStatusCode(ex.getStatusCode());
                exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                DataBuffer dataBuffer = exchange.getResponse().bufferFactory().wrap(ex.getMessage().getBytes(StandardCharsets.UTF_8));
                return exchange.getResponse().writeWith(Mono.just(dataBuffer));
            }
            return Mono.error(error);
        });
    }
}
