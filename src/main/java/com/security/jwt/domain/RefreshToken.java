package com.security.jwt.domain;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class RefreshToken {
    private Long id;
    private String username;
    private String token;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
}
