package com.security.jwt.mapper;

import com.security.jwt.domain.User;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {
    @Select("SELECT * FROM users_jwt WHERE username = #{username}")
    User findByUsername(String username);

    @Insert("INSERT INTO users_jwt (username, password, role) VALUES (#{username}, #{password}, #{role})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    Integer insertUser(User user);
}
