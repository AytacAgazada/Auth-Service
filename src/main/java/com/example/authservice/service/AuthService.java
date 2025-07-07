package com.example.authservice.service;

import com.example.authservice.exception.InvalidCredentialsException;
import com.example.authservice.exception.UserAlreadyExistsException;
import com.example.authservice.exception.TokenRefreshException;
import com.example.authservice.exception.OtpException;
import com.example.authservice.mapper.UserMapper;
import com.example.authservice.model.dto.LoginRequest;
import com.example.authservice.model.dto.AuthResponse;
import com.example.authservice.model.dto.SignupRequest;
import com.example.authservice.model.dto.OtpSendRequest;
import com.example.authservice.model.dto.OtpVerificationRequest;
import com.example.authservice.model.dto.ResetPasswordRequest;
import com.example.authservice.model.entity.ConfirmationToken;
import com.example.authservice.model.entity.RefreshToken;
import com.example.authservice.model.entity.User;
import com.example.authservice.model.enumeration.Role; // Role enum-u import edirik
import com.example.authservice.repository.ConfirmationTokenRepository;
import com.example.authservice.repository.RefreshTokenRepository;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.security.jwt.JwtUtils;
import com.example.authservice.security.services.UserDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.stream.Collectors;

@Service
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final RefreshTokenRepository refreshTokenRepository;
    private final EmailService emailService;
    private final WhatsAppService whatsAppService; // WhatsAppService saxlanıldı
    private final ConfirmationTokenRepository confirmationTokenRepository;

    @Value("${otp.expiration-seconds}")
    private long otpExpirationSeconds;

    // Konstruktor Spring tərəfindən inject edilən dependency-ləri alır.
    // TelegramService artıq yoxdur.
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, UserMapper userMapper,
                       AuthenticationManager authenticationManager, JwtUtils jwtUtils,
                       RefreshTokenRepository refreshTokenRepository, EmailService emailService,
                       WhatsAppService whatsAppService,
                       ConfirmationTokenRepository confirmationTokenRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.refreshTokenRepository = refreshTokenRepository;
        this.emailService = emailService;
        this.whatsAppService = whatsAppService;
        this.confirmationTokenRepository = confirmationTokenRepository;
    }

    /**
     * Yeni istifadəçini qeydiyyatdan keçirir.
     * FIN, Username, Email və ya Phone artıq mövcuddursa UserAlreadyExistsException atır.
     * İstifadəçiyə default olaraq `ROLE_USER` rolunu təyin edir.
     *
     * @param signupRequest Qeydiyyat məlumatları (username, fin, password, email, phone, whatsappId)
     * @return Yaradılan istifadəçi obyekti
     */
    @Transactional
    public User registerUser(SignupRequest signupRequest) {
        if (userRepository.existsByFin(signupRequest.getFin())) {
            throw new UserAlreadyExistsException("FIN", signupRequest.getFin());
        }
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            throw new UserAlreadyExistsException("Username", signupRequest.getUsername());
        }
        if (signupRequest.getEmail() != null && !signupRequest.getEmail().trim().isEmpty() &&
                userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new UserAlreadyExistsException("Email", signupRequest.getEmail());
        }
        if (signupRequest.getPhone() != null && !signupRequest.getPhone().trim().isEmpty() &&
                userRepository.existsByPhone(signupRequest.getPhone())) {
            throw new UserAlreadyExistsException("Phone", signupRequest.getPhone());
        }

        User user = userMapper.toEntity(signupRequest);
        user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
        user.setRole(Role.USER); // Qeydiyyat zamanı default olaraq USER rolu təyin edilir
        user.setEnabled(false); // Hesab default olaraq passivdir, OTP ilə təsdiqlənməlidir
        // user.setTelegramChatId(signupRequest.getTelegramChatId()); // Telegram silindiyi üçün bu sətri silmək olar
        user.setWhatsappId(signupRequest.getWhatsappId());

        return userRepository.save(user);
    }

    /**
     * İstifadəçiyə OTP kodu göndərir.
     * OTP tipi (ACCOUNT_CONFIRMATION, PASSWORD_RESET) və göndərmə metodu (email, phone) seçilir.
     *
     * @param otpSendRequest OTP göndərmə tələbi (identifier, otpType, sendMethod)
     */
    @Transactional
    public void sendOtp(OtpSendRequest otpSendRequest) {
        User user = findUserByIdentifier(otpSendRequest.getIdentifier());

        String otpType = otpSendRequest.getOtpType().toUpperCase();
        String purpose = "";

        if (otpType.equalsIgnoreCase("ACCOUNT_CONFIRMATION")) {
            if (user.isEnabled()) {
                throw new OtpException("Hesab artıq təsdiqlənib.");
            }
            purpose = "hesab təsdiqi";
        } else if (otpType.equalsIgnoreCase("PASSWORD_RESET")) {
            purpose = "şifrə sıfırlama";
        } else {
            throw new OtpException("Yanlış OTP tipi: " + otpType);
        }

        // Əvvəlki eyni tipli OTP-ləri təmizləyirik
        confirmationTokenRepository.deleteAllByUserIdAndType(user.getId(), otpType);

        String otpCode = generateOtpCode();
        ConfirmationToken confirmationToken = new ConfirmationToken(user, otpCode, otpType, otpExpirationSeconds);
        confirmationTokenRepository.save(confirmationToken);

        String sendMethod = otpSendRequest.getSendMethod().toLowerCase();

        switch (sendMethod) {
            case "email":
                if (user.getEmail() == null || user.getEmail().trim().isEmpty()) {
                    throw new OtpException("Bu istifadəçi üçün qeydə alınmış email ünvanı yoxdur.");
                }
                String emailBody = "Salam " + user.getActualUsername() + ",<br><br>"
                        + "Sizin " + purpose + " üçün təsdiq kodunuz: <h1>" + otpCode + "</h1><br>"
                        + "Bu kod " + (otpExpirationSeconds / 60) + " dəqiqə ərzində etibarlıdır.<br><br>"
                        + "Hörmətlə,<br>"
                        + "AuthService Komandası";
                emailService.sendEmail(user.getEmail(), "Təsdiq Kodu - AuthService", emailBody);
                log.info("Email OTP sent to {}: {}", user.getEmail(), otpCode);
                break;
            case "phone":
                // Yalnız WhatsApp ilə göndərməyə icazə veririk
                if (user.getWhatsappId() != null && !user.getWhatsappId().trim().isEmpty()) {
                    whatsAppService.sendOtpMessage(user.getWhatsappId(), otpCode, purpose);
                    log.info("WhatsApp OTP sent to {}: {}", user.getWhatsappId(), otpCode);
                } else {
                    // Telegram inteqrasiyası silindiyi üçün yalnız WhatsApp yoxlanılır
                    throw new OtpException("Telefon vasitəsilə OTP göndərilə bilmədi. İstifadəçi üçün WhatsApp ID qeydə alınmayıb.");
                }
                break;
            default:
                throw new OtpException("Yanlış göndərmə metodu. 'email' və ya 'phone' olmalıdır.");
        }
    }

    /**
     * Göndərilmiş OTP kodunu təsdiqləyir.
     * Hesab təsdiqlənməsi və ya şifrə sıfırlaması üçün istifadə olunur.
     *
     * @param otpVerificationRequest OTP təsdiqləmə tələbi (identifier, otpCode, otpType)
     */
    @Transactional
    public void verifyOtp(OtpVerificationRequest otpVerificationRequest) {
        User user = findUserByIdentifier(otpVerificationRequest.getIdentifier());

        ConfirmationToken confirmationToken = confirmationTokenRepository
                .findByTokenAndTypeAndUsedFalseAndExpiresAtAfter(
                        otpVerificationRequest.getOtpCode(),
                        otpVerificationRequest.getOtpType().toUpperCase(),
                        Instant.now())
                .orElseThrow(() -> new OtpException("Yanlış, istifadə olunmuş və ya müddəti bitmiş OTP kodu."));

        if (!Objects.equals(confirmationToken.getUser().getId(), user.getId())) {
            throw new OtpException("Bu OTP kodu başqa istifadəçiyə aiddir.");
        }

        if (otpVerificationRequest.getOtpType().equalsIgnoreCase("ACCOUNT_CONFIRMATION")) {
            user.setEnabled(true); // Hesabı aktiv edirik
            userRepository.save(user);
            confirmationToken.setConfirmedAt(Instant.now());
            confirmationToken.setUsed(true); // OTP-ni istifadə olunmuş kimi işarələyirik
            confirmationTokenRepository.save(confirmationToken);
            log.info("Account confirmation successful for user: {}", user.getFin());
        } else if (otpVerificationRequest.getOtpType().equalsIgnoreCase("PASSWORD_RESET")) {
            confirmationToken.setConfirmedAt(Instant.now());
            confirmationToken.setUsed(true); // OTP-ni istifadə olunmuş kimi işarələyirik
            confirmationTokenRepository.save(confirmationToken);
            log.info("Password Reset OTP verified for user: {}", user.getFin());
        } else {
            throw new OtpException("Yanlış OTP tipi.");
        }
    }

    /**
     * Şifrə sıfırlama OTP-si təsdiqləndikdən sonra istifadəçinin şifrəsini sıfırlayır.
     *
     * @param request Yeni şifrə və OTP kodu
     */
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        if (!request.getNewPassword().equals(request.getNewPasswordConfirmation())) {
            throw new OtpException("Yeni parollar üst-üstə düşmür.");
        }

        User user = findUserByIdentifier(request.getIdentifier());

        ConfirmationToken confirmationToken = confirmationTokenRepository
                .findByTokenAndTypeAndUsedFalseAndExpiresAtAfter(
                        request.getOtpCode(),
                        "PASSWORD_RESET",
                        Instant.now())
                .orElseThrow(() -> new OtpException("Şifrə sıfırlama OTP kodu yanlış, müddəti bitmiş və ya istifadə olunmuşdur. Zəhmət olmasa yenidən cəhd edin."));

        if (!Objects.equals(confirmationToken.getUser().getId(), user.getId())) {
            throw new OtpException("Bu OTP kodu başqa istifadəçiyə aiddir.");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        confirmationToken.setUsed(true);
        confirmationTokenRepository.save(confirmationToken);
        log.info("Password successfully reset for user: {}", user.getFin());
    }

    /**
     * İstifadəçinin identifikasiya məlumatları ilə (FIN, username, email) autentifikasiya edir.
     * JWT Access Token və Refresh Token qaytarır.
     *
     * @param loginRequest Login məlumatları (identifier, password)
     * @param request HTTP request obyekti (User-Agent və IP almaq üçün)
     * @return Autentifikasiya cavabı (JWT tokenlər və istifadəçi məlumatları)
     */
    @Transactional
    public AuthResponse authenticateUser(LoginRequest loginRequest, HttpServletRequest request) {
        User user = findUserByIdentifier(loginRequest.getIdentifier());

        if (!user.isEnabled()) {
            throw new InvalidCredentialsException("Hesab aktiv deyil. Zəhmət olmasa hesabınızı təsdiqləyin.");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getIdentifier(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwt = jwtUtils.generateTokenFromUsername(userDetails.getUsername());

        String userAgent = request.getHeader("User-Agent");
        String ipAddress = request.getRemoteAddr();

        RefreshToken refreshToken = refreshTokenRepository.findByUserAndUserAgent(user, userAgent)
                .map(existingToken -> {
                    existingToken.setExpiryDate(Instant.now().plusMillis(jwtUtils.getRefreshTokenExpirationMs()));
                    existingToken.setIpAddress(ipAddress);
                    return refreshTokenRepository.save(existingToken);
                })
                .orElseGet(() -> jwtUtils.createRefreshToken(user, userAgent, ipAddress));

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new AuthResponse(
                jwt,
                refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getActualUsername(),
                userDetails.getUsername(), // FIN
                userDetails.getEmail(),
                userDetails.getPhone(),
                roles
        );
    }

    /**
     * Refresh Token vasitəsilə yeni Access Token yaradır.
     * Refresh Token-in etibarlılığını və istifadəçi agenti/IP adresini yoxlayır.
     *
     * @param requestRefreshToken Refresh Token stringi
     * @param request HTTP request obyekti (User-Agent və IP almaq üçün)
     * @return Autentifikasiya cavabı (yeni Access Token və eyni Refresh Token)
     */
    @Transactional
    public AuthResponse refreshAccessToken(String requestRefreshToken, HttpServletRequest request) {
        RefreshToken refreshToken = jwtUtils.verifyRefreshToken(requestRefreshToken);

        User user = refreshToken.getUser();

        String currentUserAgent = request.getHeader("User-Agent");
        String currentIpAddress = request.getRemoteAddr();

        // Refresh token-in başqa cihazdan və ya IP-dən istifadə edilib-edilmədiyini yoxlayır
        if (!refreshToken.getUserAgent().equals(currentUserAgent) || !refreshToken.getIpAddress().equals(currentIpAddress)) {
            refreshTokenRepository.delete(refreshToken); // Şübhəli tokeni silir
            throw new TokenRefreshException(requestRefreshToken, "Refresh token fərqli cihazdan və ya IP adresindən istifadə edildi!");
        }

        String newAccessToken = jwtUtils.generateTokenFromUsername(user.getFin());

        // Refresh tokenin müddətini yeniləyir
        refreshToken.setExpiryDate(Instant.now().plusMillis(jwtUtils.getRefreshTokenExpirationMs()));
        refreshTokenRepository.save(refreshToken);

        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new AuthResponse(
                newAccessToken,
                refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getActualUsername(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                userDetails.getPhone(),
                roles
        );
    }

    /**
     * Cari istifadəçinin bütün refresh tokenlərini ləğv edərək çıxışını təmin edir.
     *
     * @param userId Çıxış edən istifadəçinin ID-si
     */
    @Transactional
    public void logoutUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Çıxış üçün istifadəçi tapılmadı."));

        int deletedCount = refreshTokenRepository.deleteByUser(user);
        log.info("İstifadəçi {} üçün {} refresh token silindi.", userId, deletedCount);
    }

    /**
     * FIN, email və ya username vasitəsilə istifadəçini tapır.
     *
     * @param identifier İstifadəçinin FIN, email və ya username-i
     * @return Tapılan istifadəçi obyekti
     * @throws InvalidCredentialsException İstifadəçi tapılmazsa
     */
    private User findUserByIdentifier(String identifier) {
        return userRepository.findByFin(identifier)
                .orElseGet(() -> userRepository.findByEmail(identifier)
                        .orElseGet(() -> userRepository.findByUsername(identifier)
                                .orElseThrow(() -> new InvalidCredentialsException("İstifadəçi tapılmadı."))));
    }

    /**
     * 6 rəqəmli OTP kodu yaradır.
     *
     * @return Yaradılan OTP kodu
     */
    private String generateOtpCode() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(999999));
    }
}