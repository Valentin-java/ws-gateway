package com.workers.wsgateway.config.security.common;

import com.workers.wsgateway.config.security.filter.TokenAuthenticationFilterWebFlux;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final TokenAuthenticationFilterWebFlux tokenAuthenticationFilter;

    private static final String[] WHITELIST = {
            "/actuator/health",
            "/actuator/prometheus",
            "/advisor/**",
            "/swagger-ui/**",
            "/specs/**",
            "/ws-user-management/**"
    };

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(WHITELIST).permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterAt(tokenAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
}
