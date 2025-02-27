package com.security.jwt.controller;

import com.security.jwt.service.UserService;
import com.security.jwt.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtil jwtUtil;

    private final UserService userService;

    @PostMapping("/login")
    public String login(@RequestParam("username") String username, @RequestParam("password") String password
        , HttpServletResponse response, RedirectAttributes redirectAttributes) {
        String authenticate = userService.authenticate(username, password);
        String[] tokenArr = authenticate.split(":");
        String accessToken = tokenArr[0];
        String refreshToken = tokenArr[1];

        // AccessToken을 쿠키에 저장
        Cookie accessCookie = new Cookie("accessToken", accessToken);
        accessCookie.setPath("/");
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(true);

        // Refresh Token을 쿠키게 저장
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        refreshCookie.setPath("/");
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);

        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
        redirectAttributes.addAttribute("username", username);
        return "redirect:/pass";
    }

    @PostMapping("/logout")
    public String logout(HttpServletResponse response) {
        // Access Token 쿠키 삭제
        Cookie accessCookie = new Cookie("accessToken", null);
        accessCookie.setPath("/");
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(true);
        accessCookie.setMaxAge(0);

        // Refresh Token을 쿠키게 저장
        Cookie refreshCookie = new Cookie("refreshToken", null);
        refreshCookie.setPath("/");
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);
        refreshCookie.setMaxAge(0);

        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);

        return "redirect:/";
    }

    @PostMapping("/refresh")
    public String refresh(@CookieValue("refreshToken") String refreshToken, HttpServletResponse response) {
        try {
            String newAccessToken = jwtUtil.refreshAccessToken(refreshToken);

            // 새 Access Token 쿠키에 저장
            Cookie accessCookie = new Cookie("accessToken", newAccessToken);
            accessCookie.setPath("/");
            accessCookie.setHttpOnly(true);
            accessCookie.setSecure(true);

            response.addCookie(accessCookie);
            return "redirect:/pass";
        } catch (Exception e){
            return "redirect:/";
        }
    }
}
