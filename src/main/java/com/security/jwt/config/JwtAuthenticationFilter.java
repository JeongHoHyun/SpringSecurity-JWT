package com.security.jwt.config;

import com.security.jwt.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final List<String> EXCLUDE_URLS = List.of("/auth/login", "/auth/logout", "/", "/register", "/css/**", "/js/**", "/img/**");

    private final JwtUtil jwtUtil;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return EXCLUDE_URLS.contains(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = null;
        String refreshToken = null;
        // 요청에서 쿠키 가져오기
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("accessToken")) {
                    accessToken = cookie.getValue();
                } else if (cookie.getName().equals("refreshToken")) {
                    refreshToken = cookie.getValue();
                }
            }
        }

        if(accessToken == null || !jwtUtil.validateAccessToken(accessToken)){
            if (refreshToken != null && jwtUtil.validateRefreshToken(refreshToken)){
                String newAccessToken = jwtUtil.refreshAccessToken(refreshToken);
                setAccessTokenCookie(response, newAccessToken);
                setSecurityContext(jwtUtil.getClaims(newAccessToken).getSubject());
            } else {
                response.sendRedirect("/");
                return;
            }
        }

        Claims claims = jwtUtil.getClaims(accessToken);
        setSecurityContext(claims.getSubject());
        filterChain.doFilter(request, response);
    }

    private void setSecurityContext(String username) {
        UserDetails userDetails = User.withUsername(username)
                .password("")
                .authorities("ROLE_USER")
                .build();
        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthentication(username, userDetails.getAuthorities())
        );
    }

    private void setAccessTokenCookie(HttpServletResponse response, String accessToken) {
        Cookie accessCookie = new Cookie("accessToken", accessToken);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(true);
        accessCookie.setPath("/");
        response.addCookie(accessCookie);
    }
}
