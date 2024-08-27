package com.example.demolevan.util;


import com.example.demolevan.entity.User;
import com.example.demolevan.jwt.JwtService;
import com.example.demolevan.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
public class BlockLoginIpHelper {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private final Map<String, Integer> unsuccessfulLoginAttempts;
    private final Map<String, Long> blockedIPs;

    private static final long BLOCK_DURATION = 5 * 60 * 1000;

    public BlockLoginIpHelper(JwtService jwtService, UserRepository userRepository, Map<String, Integer> unsuccessfulLoginAttempts, Map<String, Long> blockedIPs) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.unsuccessfulLoginAttempts = unsuccessfulLoginAttempts;
        this.blockedIPs = blockedIPs;
    }

    public ResponseEntity<String> generateTokenResponse(String username) {
        User user = userRepository.findByUsername(username);
        Map<String, Object> extraClaims = new HashMap<>();
        String token = jwtService.generateToken(user, extraClaims);
        log.debug("Generated JWT token for user '{}': {}", username, token);
        return ResponseEntity.ok(token);
    }

    public boolean isIPBlocked(String clientIP) {
        Long unblockTime = blockedIPs.get(clientIP);
        return unblockTime != null && unblockTime > System.currentTimeMillis();
    }

    public void blockIP(String clientIP) {
        blockedIPs.put(clientIP, System.currentTimeMillis() + BLOCK_DURATION);
        unsuccessfulLoginAttempts.remove(clientIP);
    }

    public String extractTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7); // Remove "Bearer " prefix from token
        }
        return null;
    }

    public String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        return xfHeader != null ? xfHeader.split(",")[0] : request.getRemoteAddr();
    }
}

