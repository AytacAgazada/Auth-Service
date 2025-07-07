package com.example.authservice.model.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "Identifier (username, FIN or email) cannot be blank")
    private String identifier;

    @NotBlank(message = "Password cannot be blank")
    private String password;

    private Boolean rememberMe = false;



}