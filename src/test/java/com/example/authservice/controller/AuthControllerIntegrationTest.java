package com.example.authservice.controller;

import com.example.authservice.model.dto.*;
import com.example.authservice.model.entity.ConfirmationToken;
import com.example.authservice.model.entity.User;
import com.example.authservice.model.enumeration.Role;
import com.example.authservice.repository.ConfirmationTokenRepository;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.service.EmailService;
import com.example.authservice.service.WhatsAppService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test") // application-test.yml faylını aktiv edir
public class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // EmailService və WhatsAppService mock edilir, çünki integration testlərdə
    // real email/WhatsApp göndərmək istəmirik.
    @MockBean
    private EmailService emailService;

    @MockBean
    private WhatsAppService whatsAppService;


    @BeforeEach
    void setUp() {
        userRepository.deleteAll(); // Hər testdən əvvəl bütün istifadəçiləri silir
        confirmationTokenRepository.deleteAll(); // Hər testdən əvvəl bütün tokenləri silir
    }

    @AfterEach
    void tearDown() {
        userRepository.deleteAll(); // Hər testdən sonra bütün istifadəçiləri silir
        confirmationTokenRepository.deleteAll(); // Hər testdən sonra bütün tokenləri silir
    }

    // Helper metodlar
    private SignupRequest createSignupRequest(String username, String fin, String password, String email) {
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername(username);
        signupRequest.setFin(fin);
        signupRequest.setPassword(password);
        signupRequest.setConfirmPassword(password);
        signupRequest.setEmail(email);
        return signupRequest;
    }

    private LoginRequest createLoginRequest(String identifier, String password) {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setIdentifier(identifier);
        loginRequest.setPassword(password);
        return loginRequest;
    }

    // Test Ssenariləri

    @Test
    void testUserSignupAndLoginFlow() throws Exception {
        // 1. İstifadəçi qeydiyyatı
        SignupRequest signupRequest = createSignupRequest("testuser", "1234567", "password123", "testuser@example.com");

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isCreated()); // 201 Created gözləyirik

        // Login is tried before account confirmation, should fail (401 Unauthorized)
        LoginRequest loginRequest = createLoginRequest("1234567", "password123");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());

        // 2. Hesab təsdiqi üçün OTP göndərmə
        User user = userRepository.findByFin("1234567").orElseThrow(() -> new AssertionError("User not found after signup"));
        OtpSendRequest otpSendRequest = new OtpSendRequest();
        otpSendRequest.setIdentifier(user.getFin());
        otpSendRequest.setOtpType("ACCOUNT_CONFIRMATION");
        otpSendRequest.setSendMethod("email");

        mockMvc.perform(post("/api/auth/otp/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otpSendRequest)))
                .andExpect(status().isOk());

        // Göndərilən OTP-ni database-dən götürürük
        ConfirmationToken confirmationToken = confirmationTokenRepository.findByUserIdAndTypeAndUsedFalseAndExpiresAtAfter(
                        user.getId(), "ACCOUNT_CONFIRMATION", Instant.now())
                .orElseThrow(() -> new AssertionError("Confirmation token not found after sending OTP"));

        // 3. OTP-ni təsdiqləmə
        OtpVerificationRequest otpVerificationRequest = new OtpVerificationRequest();
        otpVerificationRequest.setIdentifier(user.getFin());
        otpVerificationRequest.setOtpCode(confirmationToken.getToken());
        otpVerificationRequest.setOtpType("ACCOUNT_CONFIRMATION");

        mockMvc.perform(post("/api/auth/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otpVerificationRequest)))
                .andExpect(status().isOk());

        // 4. Hesab təsdiqləndikdən sonra login cəhdi (uğurlu olmalıdır)
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseString = loginResult.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(responseString, AuthResponse.class);
        assertNotNull(authResponse.getAccessToken());
        assertNotNull(authResponse.getRefreshToken());
        assertTrue(authResponse.getRoles().contains("USER")); // USER rolu daxil olmalıdır
    }

    @Test
    void testFailedSignup_UserExists() throws Exception {
        // İlk qeydiyyat uğurludur
        SignupRequest signupRequest = createSignupRequest("existinguser", "1111111", "password123", "existing@example.com");
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isCreated());

        // Eyni FIN ilə təkrar qeydiyyat cəhdi (409 Conflict gözlənilir)
        SignupRequest duplicateFinSignup = createSignupRequest("anotheruser", "1111111", "password456", "another@example.com");
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicateFinSignup)))
                .andExpect(status().isConflict());

        // Eyni Username ilə təkrar qeydiyyat cəhdi (409 Conflict gözlənilir)
        SignupRequest duplicateUsernameSignup = createSignupRequest("existinguser", "2222222", "password456", "second@example.com");
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicateUsernameSignup)))
                .andExpect(status().isConflict());

        // Eyni Email ilə təkrar qeydiyyat cəhdi (409 Conflict gözlənilir)
        SignupRequest duplicateEmailSignup = createSignupRequest("thirduser", "3333333", "password456", "existing@example.com");
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicateEmailSignup)))
                .andExpect(status().isConflict());
    }

    @Test
    void testAccessAdminEndpointAsUser() throws Exception {
        // User qeydiyyatı və aktivasiyası
        SignupRequest signupRequest = createSignupRequest("plainuser", "7654321", "userpassword", "plainuser@example.com");
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isCreated());

        User user = userRepository.findByFin("7654321").orElseThrow();
        user.setEnabled(true);
        userRepository.save(user);

        // User login-i və token almaq
        LoginRequest loginRequest = createLoginRequest("7654321", "userpassword");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String loginResponseContent = loginResult.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(loginResponseContent, AuthResponse.class);
        String accessToken = authResponse.getAccessToken();

        // ADMIN endpointinə USER rolu ilə daxil olmağa cəhd (403 Forbidden gözlənilir)
        mockMvc.perform(get("/api/auth/admin/dashboard")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    void testAccessAdminEndpointAsAdmin() throws Exception {
        // Test üçün birbaşa ADMIN rolunda istifadəçi yaradırıq
        User adminUser = User.builder()
                .username("adminuser")
                .fin("9876543")
                .password(passwordEncoder.encode("adminpassword")) // Parolu şifrələməyi unutmayın!
                .email("admin@example.com")
                .role(Role.ADMIN) // Rolu ADMIN olaraq təyin edirik
                .enabled(true)
                .createdAt(Instant.now())
                .build();
        userRepository.save(adminUser);

        // ADMIN istifadəçi login-i
        LoginRequest loginRequest = createLoginRequest("9876543", "adminpassword");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String loginResponseContent = loginResult.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(loginResponseContent, AuthResponse.class);
        String accessToken = authResponse.getAccessToken();
        assertTrue(authResponse.getRoles().contains("ADMIN")); // Cavabda ADMIN rolunun olduğunu yoxlayırıq

        // ADMIN endpointinə daxil olma (200 OK gözlənilir)
        mockMvc.perform(get("/api/auth/admin/dashboard")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    void testPasswordResetFlow() throws Exception {
        // İstifadəçi qeydiyyatı
        SignupRequest signupRequest = createSignupRequest("resetuser", "2222222", "oldpassword", "reset@example.com");
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isCreated());

        User user = userRepository.findByFin("2222222").orElseThrow();
        user.setEnabled(true); // Şifrə sıfırlaması üçün istifadəçinin aktiv olması vacibdir
        userRepository.save(user);

        // 1. Şifrə sıfırlama üçün OTP göndərmə
        OtpSendRequest otpSendRequest = new OtpSendRequest();
        otpSendRequest.setIdentifier(user.getFin());
        otpSendRequest.setOtpType("PASSWORD_RESET");
        otpSendRequest.setSendMethod("email");

        mockMvc.perform(post("/api/auth/otp/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otpSendRequest)))
                .andExpect(status().isOk());

        // Göndərilən OTP-ni database-dən götürürük
        ConfirmationToken passwordResetToken = confirmationTokenRepository.findByUserIdAndTypeAndUsedFalseAndExpiresAtAfter(
                        user.getId(), "PASSWORD_RESET", Instant.now())
                .orElseThrow(() -> new AssertionError("Password reset token not found after sending OTP"));

        // 2. Şifrə sıfırlama OTP-sini təsdiqləmə
        OtpVerificationRequest otpVerificationRequest = new OtpVerificationRequest();
        otpVerificationRequest.setIdentifier(user.getFin());
        otpVerificationRequest.setOtpCode(passwordResetToken.getToken());
        otpVerificationRequest.setOtpType("PASSWORD_RESET");

        mockMvc.perform(post("/api/auth/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otpVerificationRequest)))
                .andExpect(status().isOk());

        // 3. Şifrəni sıfırlama
        ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
        resetPasswordRequest.setIdentifier(user.getFin());
        resetPasswordRequest.setOtpCode(passwordResetToken.getToken());
        resetPasswordRequest.setNewPassword("newpassword123");
        resetPasswordRequest.setNewPasswordConfirmation("newpassword123");

        mockMvc.perform(post("/api/auth/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                .andExpect(status().isOk());

        // Köhnə parolun işləmədiyini yoxlayırıq
        LoginRequest loginWithOldPassword = createLoginRequest(user.getFin(), "oldpassword");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginWithOldPassword)))
                .andExpect(status().isUnauthorized()); // 401 Unauthorized gözlənilir

        // Yeni parolun işlədiyini yoxlayırıq
        LoginRequest loginWithNewPassword = createLoginRequest(user.getFin(), "newpassword123");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginWithNewPassword)))
                .andExpect(status().isOk()); // 200 OK gözlənilir
    }

    @Test
    void testRefreshTokenFlow() throws Exception {
        // İstifadəçi qeydiyyatı və aktivasiyası
        SignupRequest signupRequest = createSignupRequest("refreshuser", "3333333", "password123", "refresh@example.com");
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isCreated());

        User user = userRepository.findByFin("3333333").orElseThrow();
        user.setEnabled(true);
        userRepository.save(user);

        // Login edib Access və Refresh Tokenləri almaq
        LoginRequest loginRequest = createLoginRequest("3333333", "password123");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String loginResponseContent = loginResult.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(loginResponseContent, AuthResponse.class);
        String refreshToken = authResponse.getRefreshToken();
        assertNotNull(refreshToken);

        // Refresh token ilə yeni Access Token almaq
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
        refreshRequest.setRefreshToken(refreshToken);

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String refreshResponseContent = refreshResult.getResponse().getContentAsString();
        AuthResponse refreshedAuthResponse = objectMapper.readValue(refreshResponseContent, AuthResponse.class);
        assertNotNull(refreshedAuthResponse.getAccessToken());
        assertEquals(refreshToken, refreshedAuthResponse.getRefreshToken()); // Refresh token eyni qalmalıdır
        assertNotEquals(authResponse.getAccessToken(), refreshedAuthResponse.getAccessToken()); // Access token fərqli olmalıdır
    }
}