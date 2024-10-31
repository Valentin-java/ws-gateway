package com.workers.wsgateway.config.security.filter;

import com.workers.wsgateway.config.security.context.AuthenticationFilterWebFluxContext;
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

import java.util.ArrayList;
import java.util.List;

import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.getUsername;
import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.whenHeaderMissing;
import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.whenTokenExpired;
import static com.workers.wsgateway.config.security.util.SecurityValidationWebFluxUtil.whenUsernameMissing;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Slf4j
@Component
public class TokenAuthenticationFilterWebFlux implements WebFilter {

    private static final List<String> WHITELIST = List.of(
            "/actuator/health",
            "/actuator/prometheus",
            "/advisor",
            "/swagger-ui",
            "/specs",
            "/ws-user-management/v1/auth/customer/sign-in",
            "/ws-user-management/v1/auth/customer/otp/sign-in",
            "/ws-user-management/v1/auth/customer/sign-up",
            "/ws-user-management/v1/auth/customer/verify/sign-up",
            "/ws-user-management/v1/auth/handyman/otp/sign-in",
            "/ws-user-management/v1/auth/handyman/sign-in",
            "/ws-user-management/v1/auth/handyman/sign-up",
            "/ws-user-management/v1/auth/handyman/verify/sign-up",
            "/ws-user-management/v1/auth/restore/reset",
            "/ws-user-management/v1/auth/restore/otp",
            "/ws-user-management/v1/auth/restore/setpass"
    );

    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange,
                             @NonNull WebFilterChain chain) {
        log.debug("[doFilterInternal] Start method");
        if (!WHITELIST.contains(exchange.getRequest().getPath().value())) {
            return doFilterRequest(exchange, chain);
        } else {
            return chain.filter(exchange);
        }
    }

    private Mono<Void> doFilterRequest(ServerWebExchange exchange, WebFilterChain chain) {
        return createContextFilter(exchange, chain)
                .flatMap(this::validateHeader)
                .flatMap(this::validateUsername)
                .flatMap(this::validateTokenExpiration)
                .flatMap(this::setAuthenticationContext)
                .flatMap(authentication -> continueFilterChain(exchange, chain, authentication))
                .onErrorResume(e -> breakFilterChain(exchange, e));
    }

    private static Mono<Void> continueFilterChain(ServerWebExchange exchange, WebFilterChain chain, Authentication authentication) {
        log.debug("[filter] Authentication successful, proceeding with request");
        return chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
    }

    private static Mono<Void> breakFilterChain(ServerWebExchange exchange, Throwable e) {
        log.error("[TokenAuthenticationFilter] Authentication error", e);

        exchange.getResponse().setStatusCode(UNAUTHORIZED);
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(e.getMessage().getBytes()))
        );
    }

    private Mono<AuthenticationFilterWebFluxContext> createContextFilter(ServerWebExchange exchange, WebFilterChain chain) {
        return Mono.just(new AuthenticationFilterWebFluxContext(exchange, chain));
    }

    private Mono<AuthenticationFilterWebFluxContext> validateHeader(AuthenticationFilterWebFluxContext context) {
        return Mono.just(context)
                .doOnNext(ctx -> log.debug("[validateHeader] Validating header"))
                .flatMap(ctx -> whenHeaderMissing(ctx.getExchange().getRequest()) ?
                        Mono.error(new ResponseStatusException(UNAUTHORIZED, "Отсуствует заголовок")) :
                        Mono.just(ctx))
                .doOnNext(ctx -> log.debug("[validateHeader] Header is present"));
    }

    private Mono<AuthenticationFilterWebFluxContext> validateUsername(AuthenticationFilterWebFluxContext context) {
        return Mono.just(context)
                .doOnNext(ctx -> log.debug("[validateUsername] Validating username"))
                .flatMap(ctx -> whenUsernameMissing(ctx.getExchange().getRequest()) ?
                        Mono.error(new ResponseStatusException(UNAUTHORIZED, "Отсутствует имя пользователя")) :
                        Mono.just(ctx))
                .doOnNext(ctx -> log.debug("[validateUsername] Username is present"));
    }

    private Mono<AuthenticationFilterWebFluxContext> validateTokenExpiration(AuthenticationFilterWebFluxContext context) {
        return Mono.just(context)
                .doOnNext(ctx -> log.debug("[validateTokenExpiration] Validating token expiration"))
                .flatMap(ctx -> whenTokenExpired(ctx.getExchange().getRequest()) ?
                        Mono.error(new ResponseStatusException(UNAUTHORIZED, "Время жизни токена истекло")) :
                        Mono.just(ctx))
                .doOnNext(ctx -> log.debug("[validateTokenExpiration] Token is valid"));
    }

    private Mono<Authentication> setAuthenticationContext(AuthenticationFilterWebFluxContext context) {
        return Mono.just(context)
                .doOnNext(ctx -> log.debug("[setAuthenticationContext] Setting authentication context"))
                .flatMap(ctx -> {
                    final var tokenUser = getUsername(ctx.getExchange().getRequest());
                    return tokenUser != null
                            ? Mono.just(tokenUser)
                            : Mono.error(new ResponseStatusException(UNAUTHORIZED, "Не удалось найти пользователя"));
                })
                .flatMap(user -> {
                    Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
                    log.debug("[setAuthenticationContext] Setting authentication for user: " + user);
                    return Mono.just(authentication);
                })
                .doOnNext(ctx -> log.debug("[validateTokenExpiration] Token is valid"));
    }
}
