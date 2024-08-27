package com.example.demolevan.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {

    @NotNull(message = "First name is required")
    @NotBlank(message = "First name is required")
    String username;

    @NotNull(message = "Password is required")
    @NotBlank(message = "Password is required")
    String password;
}
