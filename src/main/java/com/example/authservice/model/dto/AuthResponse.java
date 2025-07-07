package com.example.authservice.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private String type = "Bearer";
    private Long id;
    private String username;
    private String fin; // UserDetailsImpl-də username olaraq fin istifadə etdiyimiz üçün
    private String email;
    private String phone;
    private List<String> roles;

    public AuthResponse(String accessToken, String refreshToken, Long id, String username, String fin, String email, String phone, List<String> roles) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.id = id;
        this.username = username;
        this.fin = fin;
        this.email = email;
        this.phone = phone;
        this.roles = roles;
    }
}