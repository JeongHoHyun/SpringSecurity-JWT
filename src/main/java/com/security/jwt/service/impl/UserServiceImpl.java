package com.security.jwt.service.impl;

import com.security.jwt.domain.User;
import com.security.jwt.mapper.UserMapper;
import com.security.jwt.service.UserService;
import com.security.jwt.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserMapper userMapper;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    @Override
    public String authenticate(String username, String password) {
        User user = userMapper.findByUsername(username);
        log.info("LOGIN USER INFO : {}", user);
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("아이디 또는 비밀번호가 잘못되었습니다.");
        }
        String accessToken = jwtUtil.generateAccessToken(username);
        String refreshToken = jwtUtil.generateRefreshToken(username);
        return accessToken + ":" + refreshToken;
    }

    @Override
    public Integer registerUser(User user) {
        return userMapper.insertUser(user);
    }
}
