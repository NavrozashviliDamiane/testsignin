package com.example.demolevan.service.impl;

public interface AuthenticateService {

    boolean matchUserCredentials(String username, String password);
}
