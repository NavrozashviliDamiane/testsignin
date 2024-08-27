package com.example.demolevan.controller;



import com.example.demolevan.dto.LoginRequest;
import com.example.demolevan.jwt.JwtService;
import com.example.demolevan.util.BlockLoginIpHelper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@Slf4j
@RequestMapping("/api/authentication")
public class AuthenticateController {

    private final JwtService jwtService;
    private final Map<String, Integer> unsuccessfulLoginAttempts;
    private final BlockLoginIpHelper blockLoginIpHelper;

    private static final int MAX_ATTEMPTS = 3;

    public AuthenticateController(JwtService jwtService, BlockLoginIpHelper blockLoginIpHelper) {
        this.jwtService = jwtService;
        this.blockLoginIpHelper = blockLoginIpHelper;
        this.unsuccessfulLoginAttempts = new ConcurrentHashMap<>();
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        log.info("Received login request for username: {} from IP: {}", loginRequest.getUsername(), blockLoginIpHelper.getClientIP(request));

        String clientIP = blockLoginIpHelper.getClientIP(request);

        if (blockLoginIpHelper.isIPBlocked(clientIP)) {
            log.warn("IP '{}' is blocked due to too many unsuccessful login attempts.", clientIP);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("IP is blocked. Try again later.");
        }

        unsuccessfulLoginAttempts.putIfAbsent(clientIP, 0);

        boolean isAuthenticated = jwtService.authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
        if (isAuthenticated) {
            log.info("User '{}' successfully authenticated.", loginRequest.getUsername());
            unsuccessfulLoginAttempts.remove(clientIP);
            return blockLoginIpHelper.generateTokenResponse(loginRequest.getUsername());
        } else {
            log.warn("Authentication failed for user '{}' from IP '{}'.", loginRequest.getUsername(), clientIP);
            int attempts = unsuccessfulLoginAttempts.compute(clientIP, (key, value) -> value + 1);
            if (attempts >= MAX_ATTEMPTS) {
                blockLoginIpHelper.blockIP(clientIP);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        String token = jwtService.extractTokenFromRequest(request);
        if (token != null) {
            jwtService.blacklistToken(token);
            log.info("JWT token blacklisted successfully: {}", token);
            return ResponseEntity.ok("Logged out successfully");
        } else {
            return ResponseEntity.badRequest().body("Invalid token");
        }
    }
}
