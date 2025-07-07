package com.example.authservice.validation;

import com.example.authservice.model.dto.SignupRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordMatchesValidator implements ConstraintValidator<PasswordMatches, Object> {

    @Override
    public void initialize(PasswordMatches constraintAnnotation) {
        // İlkinləşdirmə yoxdur
    }

    @Override
    public boolean isValid(Object obj, ConstraintValidatorContext context) {
        // Əmin oluruq ki, obyekt SignupRequest tipindədir
        if (!(obj instanceof SignupRequest)) {
            // Bu hal normalda gözlənilmir, çünki annotasiya SignupRequest üzərində olacaq.
            // Əgər səhvən başqa tipə tətbiq olunarsa, false qaytarır.
            return false;
        }

        SignupRequest user = (SignupRequest) obj;

        // Əvvəlki @NotBlank validasiyalarının işlədiyini fərz edirik.
        // Əgər password və ya confirmPassword null olarsa,
        // bu, @NotBlank tərəfindən tutulacaq.
        // Buna görə burada əlavə null check bir o qədər vacib deyil,
        // lakin əlavə təhlükəsizlik üçün saxlaya bilərik.
        if (user.getPassword() == null || user.getConfirmPassword() == null) {
            return false; // Null parol, validasiyadan keçmir
        }

        boolean isValid = user.getPassword().equals(user.getConfirmPassword());

        if (!isValid) {
            context.disableDefaultConstraintViolation(); // Default xəta mesajını söndürürük
            context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                    .addPropertyNode("confirmPassword") // Xətanı "confirmPassword" sahəsinə əlavə edirik
                    .addConstraintViolation();
        }
        return isValid;
    }
}