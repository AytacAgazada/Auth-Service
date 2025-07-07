package com.example.authservice.model.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;

@Data
@NoArgsConstructor
@Entity
@Table(name = "confirmation_tokens")
public class ConfirmationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token; // OTP kodu

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    @Column(nullable = false)
    private Instant expiresAt;

    private Instant confirmedAt;

    @Column(nullable = false)
    private boolean used = false; // OTP-nin istifadə olunub-olunmadığını göstərir

    @Column(nullable = false)
    private String type; // ACCOUNT_CONFIRMATION, PASSWORD_RESET

    public ConfirmationToken(User user, String token, String type, long expirationSeconds) {
        this.user = user;
        this.token = token;
        this.type = type;
        this.expiresAt = Instant.now().plusSeconds(expirationSeconds);
    }
}