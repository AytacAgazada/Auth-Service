package com.example.authservice.repository;

import com.example.authservice.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findByFin(String fin);
    Optional<User> findByPhone(String phone);

    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
    Boolean existsByFin(String fin);
    Boolean existsByPhone(String phone);
}