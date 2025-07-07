package com.example.authservice.controller;

import com.example.authservice.model.dto.*;
import com.example.authservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize; // Bu importu əlavə edin
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication & Authorization", description = "User registration, login, token management and OTP operations")
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "Register a new user", description = "Creates a new user account with provided details.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User registered successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "409", description = "User with given FIN, username, email or phone already exists")
    })
    @PostMapping("/signup")
    public ResponseEntity<String> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        authService.registerUser(signupRequest);
        return new ResponseEntity<>("User registered successfully. Please confirm your account.", HttpStatus.CREATED);
    }

    @Operation(summary = "User login", description = "Authenticates a user and returns JWT access and refresh tokens.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User authenticated successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials or account not enabled"),
            @ApiResponse(responseCode = "400", description = "Invalid login request")
    })
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                                         HttpServletRequest request) {
        AuthResponse authResponse = authService.authenticateUser(loginRequest, request);
        return ResponseEntity.ok(authResponse);
    }

    @Operation(summary = "Refresh access token", description = "Generates a new access token using a valid refresh token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Access token refreshed successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token"),
            @ApiResponse(responseCode = "403", description = "Refresh token used from a different device/IP")
    })
    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshAccessToken(@Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse authResponse = authService.refreshAccessToken(request.getRefreshToken(), null); // HttpServletRequest is null here, you might want to pass it
        return ResponseEntity.ok(authResponse);
    }

    @Operation(summary = "Logout user", description = "Invalidates all refresh tokens for the current user.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User logged out successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PostMapping("/logout")
    // Bu endpointə daxil olmaq üçün autentifikasiya olunmuş hər hansı bir istifadəçi kifayətdir.
    // @PreAuthorize("isAuthenticated()") default olaraq belədir. Explicit yazmağa ehtiyac yoxdur.
    public ResponseEntity<String> logoutUser(@RequestAttribute("userId") Long userId) {
        authService.logoutUser(userId);
        return ResponseEntity.ok("User logged out successfully!");
    }

    @Operation(summary = "Send OTP", description = "Sends an OTP for account confirmation or password reset via email or phone (WhatsApp).")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP sent successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request or identifier not found"),
            @ApiResponse(responseCode = "404", description = "User not found or communication method not available")
    })
    @PostMapping("/otp/send")
    public ResponseEntity<String> sendOtp(@Valid @RequestBody OtpSendRequest otpSendRequest) {
        authService.sendOtp(otpSendRequest);
        return ResponseEntity.ok("OTP sent successfully to " + otpSendRequest.getSendMethod());
    }

    @Operation(summary = "Verify OTP", description = "Verifies the OTP code for account confirmation or password reset.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP verified successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid OTP or request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PostMapping("/otp/verify")
    public ResponseEntity<String> verifyOtp(@Valid @RequestBody OtpVerificationRequest otpVerificationRequest) {
        authService.verifyOtp(otpVerificationRequest);
        return ResponseEntity.ok("OTP verified successfully!");
    }

    @Operation(summary = "Reset password", description = "Resets user password after successful OTP verification.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request or OTP"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PostMapping("/password/reset")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        authService.resetPassword(resetPasswordRequest);
        return ResponseEntity.ok("Password reset successfully!");
    }

    // --- Rol Əsasında Giriş Məhdudiyyətləri Nümunələri ---

    @Operation(summary = "Get user profile (example for authenticated user)", description = "Retrieves the profile of the authenticated user.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User profile retrieved"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/user/profile")
    // Bu endpointə yalnız login olmuş hər hansı bir istifadəçi daxil ola bilər.
    // '@PreAuthorize("isAuthenticated()")' və ya sadəcə heç bir annotasiya qoymamaq
    // (Spring Security default olaraq JWT filterdən keçənlərə icazə verir)
    // lakin daha ekspressiv olmaq üçün yazaq.
    @PreAuthorize("isAuthenticated()") // Yalnız autentifikasiya olunmuş istifadəçilər üçün
    public ResponseEntity<String> getUserProfile() {
        // Mövcud istifadəçinin FIN-i SecurityContext-dən alına bilər
        // UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        // String fin = userDetails.getFin(); // Və ya istifadəçiyə aid digər məlumatlar
        return ResponseEntity.ok("Welcome to your profile, authenticated user!");
    }

    @Operation(summary = "Admin only endpoint", description = "Access to this endpoint is restricted to ADMIN role.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Admin content"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Requires ADMIN role")
    })
    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')") // Yalnız ADMIN roluna sahib istifadəçilər üçün
    public ResponseEntity<String> getAdminDashboard() {
        return ResponseEntity.ok("Welcome to the Admin Dashboard! (Only for ADMINs)");
    }

    @Operation(summary = "Provider only endpoint", description = "Access to this endpoint is restricted to PROVIDER role.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Provider content"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Requires PROVIDER role")
    })
    @GetMapping("/provider/info")
    @PreAuthorize("hasRole('PROVIDER')") // Yalnız PROVIDER roluna sahib istifadəçilər üçün
    public ResponseEntity<String> getProviderInfo() {
        return ResponseEntity.ok("Welcome, Provider! (Only for PROVIDERs)");
    }

    @Operation(summary = "Endpoint for Admin or Provider", description = "Access for ADMIN or PROVIDER roles.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Content for Admin or Provider"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Requires ADMIN or PROVIDER role")
    })
    @GetMapping("/admin-or-provider/data")
    @PreAuthorize("hasAnyRole('ADMIN', 'PROVIDER')") // ADMIN və ya PROVIDER rollarına sahib istifadəçilər üçün
    public ResponseEntity<String> getAdminOrProviderData() {
        return ResponseEntity.ok("This data is for ADMINs or PROVIDERs!");
    }

    @Operation(summary = "Endpoint for User or Admin", description = "Access for USER or ADMIN roles.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Content for User or Admin"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Requires USER or ADMIN role")
    })
    @GetMapping("/user-or-admin/view")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')") // USER və ya ADMIN rollarına sahib istifadəçilər üçün
    public ResponseEntity<String> getUserOrAdminView() {
        return ResponseEntity.ok("This view is for USERs or ADMINs!");
    }
}