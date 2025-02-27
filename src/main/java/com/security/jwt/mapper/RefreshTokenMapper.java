package com.security.jwt.mapper;

import com.security.jwt.domain.RefreshToken;
import org.apache.ibatis.annotations.*;

@Mapper
public interface RefreshTokenMapper {

    @Insert("INSERT INTO refresh_tokens (username, token, expires_at) VALUES (#{username}, #{token}, #{expiresAt})")
    void saveToken(RefreshToken token);

    @Select("SELECT * FROM refresh_tokens WHERE username = #{username} AND token = #{token} AND expires_at > now()")
    RefreshToken validToken(@Param("username") String username, @Param("token") String token);

    @Delete("DELETE FROM refresh_tokens WHERE token = #{token}")
    void deleteToken(@Param("token") String token);

    @Delete("DELETE FROM refresh_tokens WHERE username = #{username}")
    void deleteAllTokensByUser(@Param("username") String username);
}
