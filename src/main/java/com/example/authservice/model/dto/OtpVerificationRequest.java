package com.example.authservice.model.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OtpVerificationRequest {
    @NotBlank(message = "Identifier (username, FIN or email) cannot be blank")
    private String identifier;
    @NotBlank(message = "OTP code cannot be blank")
    private String otpCode;
    @NotBlank(message = "OTP type cannot be blank")
    private String otpType; // ACCOUNT_CONFIRMATION, PASSWORD_RESET
}