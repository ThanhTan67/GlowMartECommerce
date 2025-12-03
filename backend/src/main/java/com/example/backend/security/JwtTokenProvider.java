package com.example.backend.security;

import com.example.backend.config.JwtConfig;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;

@Service
public class JwtTokenProvider {
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtTokenProvider(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtConfig.getSecret()));
    }

    public String generateAccessToken() {

        return "";
    }

    public String generateRefreshToken() {


        return "";
    }
}
