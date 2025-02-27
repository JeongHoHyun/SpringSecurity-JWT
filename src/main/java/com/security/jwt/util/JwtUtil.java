package com.security.jwt.util;

import com.security.jwt.domain.RefreshToken;
import com.security.jwt.mapper.RefreshTokenMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    @Value("${jwt.key}")
    private String key;

    @Value("${jwt.access-expiration}")
    private Long accessExpirationTime;

    @Value("${jwt.refresh-expiration}")
    private Long refreshExpirationTime;

    private final RefreshTokenMapper refreshTokenMapper;

    private Key getKey() {
        return Keys.hmacShaKeyFor(key.getBytes());
    }

    // Access 토큰 생성
    public String generateAccessToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessExpirationTime))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Refresh 토큰 생성 및 DB 저장
    public String generateRefreshToken(String username) {
        String refreshToken = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpirationTime))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
        RefreshToken token = new RefreshToken();
        token.setUsername(username);
        token.setToken(refreshToken);
        token.setExpiresAt(LocalDateTime.now().plusSeconds(refreshExpirationTime / 1000));

        refreshTokenMapper.saveToken(token);
        return refreshToken;
    }

    // AccessToken 검증
    public boolean validateAccessToken(String accessToken) {
        try {
            Claims claims = getClaims(accessToken);
            return claims.getExpiration().after(new Date());
        } catch (ExpiredJwtException e){
            return false;
        } catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }
    // RefreshToken 검증
    public boolean validateRefreshToken(String refreshToken) {
        try {
            Claims claims = getClaims(refreshToken);
            String username = claims.getSubject();
            return refreshTokenMapper.validToken(username, refreshToken) != null;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // Refresh 토큰 검증 및 Access Token 재발급
    public String refreshAccessToken(String refreshToken) {
        Claims claims = getClaims(refreshToken);
        String username = claims.getSubject();

        RefreshToken validToken = refreshTokenMapper.validToken(username, refreshToken);
        if (validToken != null) {
            throw new RuntimeException("Refresh Token이 유효하지 않음");
        }
        return generateAccessToken(username);
    }
    // JWT 파싱
    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
