package com.example.authservice.model.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ResetPasswordRequest {
    @NotBlank(message = "Identifier (username, FIN or email) cannot be blank")
    private String identifier;
    @NotBlank(message = "OTP code cannot be blank")
    private String otpCode;
    @NotBlank(message = "New password cannot be blank")
    @Size(min = 6, max = 40, message = "New password must be between 6 and 40 characters")
    private String newPassword;
    @NotBlank(message = "New password confirmation cannot be blank")
    private String newPasswordConfirmation;
}