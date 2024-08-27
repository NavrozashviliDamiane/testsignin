package com.example.demolevan.service.impl;

import com.example.demolevan.jwt.JwtService;
import org.springframework.stereotype.Service;

@Service
public class AuthenticateServiceImpl implements AuthenticateService {

    private final JwtService jwtService;

    public AuthenticateServiceImpl(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public boolean matchUserCredentials(String username, String password) {
        return jwtService.authenticateUser(username, password);
    }
}
