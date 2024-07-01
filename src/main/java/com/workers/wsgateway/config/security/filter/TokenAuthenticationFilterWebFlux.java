package com.workers.wsgateway.config.security.filter;

import com.workers.wsgateway.config.security.context.AuthenticationFilterWebFluxContext;
import com.workers.wsgateway.config.security.context.TokenUser;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.ArrayList;

import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.getUsername;
import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.whenHeaderMissing;
import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.whenTokenExpired;
import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.whenUsernameMissing;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Slf4j
@Component
public class TokenAuthenticationFilterWebFlux implements WebFilter {

    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange,
                             @NonNull WebFilterChain chain) {
        log.debug("[doFilterInternal] Start method");
        return createContextFilter(exchange, chain)
                .flatMap(this::validateHeader)
                .flatMap(this::validateUsername)
                .flatMap(this::validateTokenExpiration)
                .flatMap(this::setAuthenticationContext)
                .flatMap(authentication -> {
                    log.debug("[filter] Authentication successful, proceeding with request");
                    return chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
                })
                .onErrorResume(e -> {
                    log.error("[TokenAuthenticationFilter] Authentication error", e);
                    return chain.filter(exchange);
                });
    }

    private Mono<AuthenticationFilterWebFluxContext> createContextFilter(ServerWebExchange exchange, WebFilterChain chain) {
        return Mono.just(new AuthenticationFilterWebFluxContext(exchange, chain));
    }

    private Mono<AuthenticationFilterWebFluxContext> validateHeader(AuthenticationFilterWebFluxContext context) {
        return Mono.defer(() -> {
            log.debug("[validateHeader] Validating header");
            if (whenHeaderMissing(context.getExchange().getRequest())) {
                log.debug("[validateHeader] Header is missing");
                return Mono.error(new ResponseStatusException(UNAUTHORIZED, "Отсуствует заголовок"));
            }
            log.debug("[validateHeader] Header is present");
            return Mono.just(context);
        });
    }

    private Mono<AuthenticationFilterWebFluxContext> validateUsername(AuthenticationFilterWebFluxContext context) {
        return Mono.defer(() -> {
            log.debug("[validateUsername] Validating username");
            try {
                if (whenUsernameMissing(context.getExchange().getRequest())) {
                    log.error("[validateUsername] Token provided but not content data!");
                    return Mono.error(new ResponseStatusException(UNAUTHORIZED, "Отсуствует имя пользователя"));
                }
            } catch (IOException e) {
                log.error("[validateUsername] Unexpected error");
                return Mono.error(new ResponseStatusException(UNAUTHORIZED, "Непредвиденная ошибка"));
            }
            log.debug("[validateUsername] Username is present");
            return Mono.just(context);
        });
    }

    private Mono<AuthenticationFilterWebFluxContext> validateTokenExpiration(AuthenticationFilterWebFluxContext context) {
        return Mono.defer(() -> {
            log.debug("[validateTokenExpiration] Validating token expiration");
            try {
                if (whenTokenExpired(context.getExchange().getRequest())) {
                    log.error("[validateTokenExpiration] Время жизни токена истекло.");
                    return Mono.error(new ResponseStatusException(UNAUTHORIZED, "Время жизни токена истекло"));
                }
            } catch (IOException e) {
                log.error("[validateTokenExpiration] Unexpected error");
                return Mono.error(new ResponseStatusException(UNAUTHORIZED, "Непредвиденная ошибка"));
            }
            log.debug("[validateTokenExpiration] Token is valid");
            return Mono.just(context);
        });
    }

    private Mono<Authentication> setAuthenticationContext(AuthenticationFilterWebFluxContext context) {
        log.debug("[setAuthenticationContext] Setting authentication context");
        TokenUser username = null;
        try {
            username = getUsername(context.getExchange().getRequest());
        } catch (IOException e) {
            log.error("[validateTokenExpiration] Unexpected error");
            return Mono.error(new ResponseStatusException(UNAUTHORIZED, "Непредвиденная ошибка"));
        }
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
        log.debug("[setAuthenticationContext] Setting authentication for user: " + username);
        return Mono.just(authentication);
    }
}
