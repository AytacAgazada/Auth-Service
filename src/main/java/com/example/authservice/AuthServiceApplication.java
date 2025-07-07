package com.example.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync; // Asinxron metodları aktivləşdirmək üçün

@SpringBootApplication
@EnableAsync // Asinxron metodları işə salır (OTP göndərmək üçün vacibdir)
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}