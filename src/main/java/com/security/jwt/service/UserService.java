package com.security.jwt.service;

import com.security.jwt.domain.User;

public interface UserService {

    public String authenticate(String username, String password);

    public Integer registerUser(User user);
}
