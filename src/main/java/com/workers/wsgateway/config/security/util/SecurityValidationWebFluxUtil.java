package com.workers.wsgateway.config.security.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.workers.wsgateway.config.security.context.TokenUser;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.io.IOException;
import java.util.Base64;
import java.util.Date;

import static com.workers.wsgateway.config.security.util.Constant.AUTH_HEADER_NAME;
import static com.workers.wsgateway.config.security.util.Constant.AUTH_TOKEN_PREFIX;

public class SecurityValidationWebFluxUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static boolean whenHeaderMissing(ServerHttpRequest context) {
        String header = getHeaderRequest(context);
        return header == null
                || !header.startsWith(AUTH_TOKEN_PREFIX);
    }

    public static boolean whenUsernameMissing(ServerHttpRequest context) {
        String header = getHeaderRequest(context);
        TokenUser username = null;
        try {
            username = getUsername(header);
        } catch (IOException e) {
            return true;
        }
        return username == null;
    }

    public static boolean whenTokenExpired(ServerHttpRequest context) {
        String header = getHeaderRequest(context);
        TokenUser user = null;
        try {
            user = getUsername(header);
        } catch (IOException e) {
            return true;
        }
        Long exp = user.getExp();
        if (exp == null) {
            return true;
        }
        return new Date(exp * 1000).before(new Date());
    }

    public static String getHeaderRequest(ServerHttpRequest context) {
        if (context.getHeaders().containsKey(AUTH_HEADER_NAME)) {
            return context.getHeaders().get(AUTH_HEADER_NAME).stream()
                    .filter(header -> header.startsWith(AUTH_TOKEN_PREFIX))
                    .findFirst()
                    .orElse(null);
        }
        return null;
    }

    public static TokenUser getUsername(ServerHttpRequest context) {
        String header = getHeaderRequest(context);
        try {
            return getUsername(header);
        } catch (IOException e) {
            return null;
        }
    }

    public static TokenUser getUsername(String header) throws IOException {
        return MAPPER.readValue(extractDecodedPayload(header), TokenUser.class);
    }

    private static byte[] extractDecodedPayload(String headerValue) {
        return Base64.getDecoder().decode(headerValue.split("\\.")[1]);
    }
}
