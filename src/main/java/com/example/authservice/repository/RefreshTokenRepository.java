package com.example.authservice.repository;

import com.example.authservice.model.entity.RefreshToken;
import com.example.authservice.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByUserAndUserAgent(User user, String userAgent);
    int deleteByUser(User user);
}