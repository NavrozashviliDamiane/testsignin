package com.example.demolevan.jwt;


import com.example.demolevan.repository.UserRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

@Slf4j
@Component
public class JwtAuthenticationFilterHelper {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final Map<String, Integer> unsuccessfulLoginAttempts;
    private final Map<String, Long> blockedIPs;

    private static final String AUTH_HEADER_PREFIX = "Bearer ";
    private static final String AUTH_HEADER = "Authorization";
    private static final String PUBLIC_ENDPOINT_PREFIX = "/api";
    private static final String[] PUBLIC_ENDPOINTS = {"/authentication", "/trainees/register", "/trainers/register", "/error"};

    public JwtAuthenticationFilterHelper(JwtService jwtService, UserRepository userRepository, Map<String, Integer> unsuccessfulLoginAttempts, Map<String, Long> blockedIPs) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.unsuccessfulLoginAttempts = unsuccessfulLoginAttempts;
        this.blockedIPs = blockedIPs;
    }

    public void processRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        CachedBodyHttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(request);
        String clientIP = getClientIP(request);

        if (isIPBlocked(clientIP)) {
            handleBlockedIP(response, clientIP);
            return;
        }

        String requestURI = request.getRequestURI();
        if (isPublicEndpoint(requestURI)) {
            filterChain.doFilter(wrappedRequest, response);
            return;
        }

        String authHeader = request.getHeader(AUTH_HEADER);
        if (authHeader == null || !authHeader.startsWith(AUTH_HEADER_PREFIX)) {
            handleUnauthorized(response);
            return;
        }

        String jwt = authHeader.substring(AUTH_HEADER_PREFIX.length());
        if (!jwtService.validateToken(jwt)) {
            handleInvalidToken(response);
            return;
        }

        String username = jwtService.extractUsername(jwt);
        UserDetails userDetails = jwtService.loadUserByUsername(username);

        processRequestBody(wrappedRequest, response, jwt, userDetails);

        filterChain.doFilter(wrappedRequest, response);
    }

    private void processRequestBody(CachedBodyHttpServletRequest wrappedRequest, HttpServletResponse response, String jwt, UserDetails userDetails) throws IOException {
        String requestBodyContent = new String(wrappedRequest.getRequestBody());
        log.info("Request body size: {}", requestBodyContent.length());
        log.info("Request body content: {}", requestBodyContent);

        if (!requestBodyContent.isEmpty()) {
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> requestBody = objectMapper.readValue(requestBodyContent, new TypeReference<Map<String, Object>>() {});
            Object requestBodyUsername = requestBody.get("username");
            log.info("Username from request body: {}", requestBodyUsername);

            if (requestBodyUsername != null && requestBodyUsername.equals(userDetails.getUsername())) {
                if (!jwtService.isTokenBlacklisted(jwt)) {
                    authenticateUser(userDetails, jwt);
                } else {
                    handleBlacklistedToken(response);
                }
            }
        }
    }

    private void authenticateUser(UserDetails userDetails, String jwt) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, jwt, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.info("Authenticated user: {}", userDetails.getUsername());
    }

    private void handleBlockedIP(HttpServletResponse response, String clientIP) throws IOException {
        String logMessage = "You are blocked for 5 min due to too many unsuccessful login attempts.";
        log.warn(logMessage);
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.getWriter().write(logMessage);
    }

    private void handleUnauthorized(HttpServletResponse response) throws IOException {
        log.info("Token not provided.");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token not provided");
    }

    private void handleInvalidToken(HttpServletResponse response) throws IOException {
        log.info("Invalid token.");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
    }

    private void handleBlacklistedToken(HttpServletResponse response) throws IOException {
        log.info("JWT token is blacklisted. Access denied.");
        response.setStatus(HttpStatus.FORBIDDEN.value());
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        return xfHeader != null ? xfHeader.split(",")[0] : request.getRemoteAddr();
    }

    private boolean isIPBlocked(String clientIP) {
        Long unblockTime = blockedIPs.get(clientIP);
        return unblockTime != null && unblockTime > System.currentTimeMillis();
    }

    private boolean isPublicEndpoint(String requestURI) {
        return Arrays.stream(PUBLIC_ENDPOINTS).anyMatch(endpoint -> requestURI.startsWith(PUBLIC_ENDPOINT_PREFIX + endpoint));
    }
}
