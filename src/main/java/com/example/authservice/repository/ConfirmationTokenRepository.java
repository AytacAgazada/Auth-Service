package com.example.authservice.repository;

import com.example.authservice.model.entity.ConfirmationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface ConfirmationTokenRepository extends JpaRepository<ConfirmationToken, Long> {

    // Mövcud metodlarınız
    Optional<ConfirmationToken> findByTokenAndTypeAndUsedFalseAndExpiresAtAfter(String token, String type, Instant now);

    @Modifying
    @Query("DELETE FROM ConfirmationToken ct WHERE ct.user.id = :userId AND ct.type = :type")
    void deleteAllByUserIdAndType(Long userId, String type);

    // AuthControllerIntegrationTest tərəfindən tələb olunan və əlavə edilməli olan metod
    // Bu metod testdəki ssenarilər üçün lazımdır:
    // - Hesab təsdiqi üçün OTP-ni tapmaq
    // - Şifrə sıfırlama üçün OTP-ni tapmaq
    Optional<ConfirmationToken> findByUserIdAndTypeAndUsedFalseAndExpiresAtAfter(Long userId, String type, Instant expiresAt);

    // Əlavə olaraq, əgər istifadəçini FIN üzərindən axtarırsınızsa (hansı ki, testdəki user.getFin() istifadə olunur),
    // bu metod da faydalı ola bilər. Lakin, testdə user.getId() istifadə olunduğu üçün
    // yuxarıdakı metod kifayətdir. Sadəcə bir nümunə olaraq saxlayıram:
    // Optional<ConfirmationToken> findByUserFinAndTypeAndUsedFalseAndExpiresAtAfter(String fin, String type, Instant expiresAt);

    // Əgər FIN üzərindən user tapıb, sonra user.getId() ilə token tapmaq istəyirsinizsə,
    // findByUserIdAndTypeAndUsedFalseAndExpiresAtAfter metodu kifayətdir.
}