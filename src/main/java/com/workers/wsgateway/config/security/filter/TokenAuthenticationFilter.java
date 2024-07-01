package com.workers.wsgateway.config.security.filter;

import com.workers.wsgateway.config.security.context.AuthenticationFilterContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Optional;

import static com.workers.wsgateway.config.security.util.SecurityValidationUtil.getUsername;
import static com.workers.wsgateway.config.security.util.SecurityValidationUtil.whenHeaderMissing;
import static com.workers.wsgateway.config.security.util.SecurityValidationUtil.whenTokenExpired;
import static com.workers.wsgateway.config.security.util.SecurityValidationUtil.whenUsernameMissing;
import static com.workers.wsgateway.util.Constants.UNEXPECTED_TEXT_ERROR;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Slf4j
@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws IOException, ServletException {

        log.debug("[doFilterInternal] Start method");
        try {
            Optional.of(createContextFilter(request, response, filterChain))
                    .map(this::validateHeader)
                    .map(this::validateUsername)
                    .map(this::validateTokenExpiration)
                    .map(this::setAuthenticationContext)
                    .ifPresent(this::continueFilterChain);
        } catch (ResponseStatusException e) {
            log.error("[TokenAuthenticationFilter] Authentication error");
            filterChain.doFilter(request, response);
        }
    }

    private AuthenticationFilterContext createContextFilter(HttpServletRequest request,
                                                            HttpServletResponse response,
                                                            FilterChain filterChain) {
        return new AuthenticationFilterContext(request, response, filterChain);
    }

    private AuthenticationFilterContext validateHeader(AuthenticationFilterContext context) {
        try {
            if (whenHeaderMissing(context)) {
                context.getFilterChain().doFilter(context.getRequest(), context.getResponse());
                return null;
            }
            return context;
        } catch (IOException | ServletException e) {
            log.error("[validateHeader] Something went wrong");
            return null;
        }
    }

    private AuthenticationFilterContext validateUsername(AuthenticationFilterContext context) {
        try {
            if (whenUsernameMissing(context)) {
                log.error("[TokenAuthenticationFilter] Token provided but not content data!");
                context.getFilterChain().doFilter(context.getRequest(), context.getResponse());
                return null;
            }
            return context;
        } catch (IOException | ServletException e) {
            log.error("[validateUsername] Something went wrong");
            return null;
        }
    }

    private AuthenticationFilterContext validateTokenExpiration(AuthenticationFilterContext context) {
        try {
            if (whenTokenExpired(context)) {
                log.error("[validateTokenExpiration] Время жизни токена истекло.");
                throw new ResponseStatusException(UNAUTHORIZED, "Время жизни токена истекло");
            }
            return context;
        } catch (IOException e) {
            log.error("[setAuthenticationContext] Something went wrong");
            return null;
        }
    }

    private AuthenticationFilterContext setAuthenticationContext(AuthenticationFilterContext context) {
        try {
            Authentication authentication = new UsernamePasswordAuthenticationToken(getUsername(context), null, new ArrayList<>());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return context;
        } catch (IOException e) {
            log.error("[setAuthenticationContext] Something went wrong");
            return null;
        }
    }

    private void continueFilterChain(AuthenticationFilterContext context) {
        try {
            context.getFilterChain().doFilter(context.getRequest(), context.getResponse());
        } catch (IOException | ServletException e) {
            log.error("[continueFilterChain] Something went wrong");
            throw new ResponseStatusException(UNAUTHORIZED, UNEXPECTED_TEXT_ERROR);
        }
    }
}
