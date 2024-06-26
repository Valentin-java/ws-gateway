//package com.workers.wsgateway.config.security;
//
//import com.workers.wsgateway.config.security.context.TokenAuthenticationFilterContext;
//import com.workers.wsgateway.util.SecurityValidationUtil;
//import io.jsonwebtoken.Claims;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.NonNull;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.apache.logging.log4j.util.Strings;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//import org.springframework.web.server.ResponseStatusException;
//
//import java.io.IOException;
//import java.util.Arrays;
//import java.util.List;
//import java.util.Optional;
//
//import static com.workers.wsgateway.util.Constants.AUTH_TOKEN_PREFIX;
//import static com.workers.wsgateway.util.Constants.UNEXPECTED_TEXT_ERROR;
//import static java.util.stream.Collectors.toList;
//import static org.springframework.http.HttpStatus.UNAUTHORIZED;
//
//@Slf4j
//@Component
//@RequiredArgsConstructor
//public class TokenAuthenticationFilter extends OncePerRequestFilter {
//
//    private final SecurityValidationUtil securityUtil;
//
//    @Override
//    protected void doFilterInternal(@NonNull HttpServletRequest request,
//                                    @NonNull HttpServletResponse response,
//                                    @NonNull FilterChain filterChain) throws IOException, ServletException {
//
//        log.debug("[doFilterInternal] Start method");
//        String path = request.getRequestURI();
//        if (path.startsWith("/ws-auth/")) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//        try {
//            Optional.of(createContextFilter(request, response, filterChain))
//                    .map(this::validateHeader)
//                    .map(this::tokenContainUsername)
//                    .map(this::validateTokenExpiration)
//                    .map(this::setAuthenticationContext)
//                    .ifPresent(this::continueFilterChain);
//        } catch (ResponseStatusException e) {
//            log.error("Authentication error: {}", e.getMessage());
//            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//            response.getWriter().write(e.getMessage());
//        }
//    }
//
//    private TokenAuthenticationFilterContext createContextFilter(HttpServletRequest request,
//                                                                 HttpServletResponse response,
//                                                                 FilterChain filterChain) {
//        return new TokenAuthenticationFilterContext(request, response, filterChain);
//    }
//
//    private TokenAuthenticationFilterContext validateHeader(TokenAuthenticationFilterContext context) {
//        String header = securityUtil.getHeaderRequest(context);
//        if (Strings.isEmpty(header)
//                || !header.startsWith(AUTH_TOKEN_PREFIX)) {
//            throw new ResponseStatusException(UNAUTHORIZED, "Отсуствует, либо заголовок, либо токен");
//        }
//        return context;
//    }
//
//    private TokenAuthenticationFilterContext tokenContainUsername(TokenAuthenticationFilterContext context) {
//        String user = securityUtil.getUsername(context);
//
//        if (user == null) {
//            log.error("Token provided but not content data!");
//            throw new ResponseStatusException(UNAUTHORIZED, "В токене отсуствует имя пользователя");
//        }
//        return context;
//    }
//
//    // Валидация токена на время жизни
//    private TokenAuthenticationFilterContext validateTokenExpiration(TokenAuthenticationFilterContext context) {
//        String token = securityUtil.getToken(context);
//        Claims claims = securityUtil.extractAllClaims(token);
//
//        if (securityUtil.isTokenExpired(claims)) {
//            log.error("[validateTokenExpiration] Время жизни токена истекло.");
//            throw new ResponseStatusException(UNAUTHORIZED, "Время жизни токена истекло");
//        }
//        return context;
//    }
//
//    private TokenAuthenticationFilterContext setAuthenticationContext(TokenAuthenticationFilterContext context) {
//        String username = securityUtil.getUsername(context);
//        log.debug("[setAuthenticationContext] UserId: {}", username);
//
//        var grantedAuthorities = getGrantedAuthority(context);
//
//        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        return context;
//    }
//
//    private List<GrantedAuthority> getGrantedAuthority(TokenAuthenticationFilterContext context) {
//        Claims claims = securityUtil.extractAllClaims(securityUtil.getToken(context));
//        String roles = (String) claims.get("roles");
//
//        return Arrays.stream(roles.split(","))
//                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
//                .collect(toList());
//    }
//
//    private void continueFilterChain(TokenAuthenticationFilterContext context) {
//        try {
//            context.getFilterChain().doFilter(context.getRequest(), context.getResponse());
//        } catch (IOException | ServletException e) {
//            throw new ResponseStatusException(UNAUTHORIZED, UNEXPECTED_TEXT_ERROR);
//        }
//    }
//}
