package com.workers.wsgateway.config.security.context;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenUser {
    private String sub;
    private Long exp;
    private String roles;
}