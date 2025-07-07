package com.example.authservice.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = OneOfFieldsNotBlankValidator.class)
@Documented
public @interface OneOfFieldsNotBlank {
    String message() default "At least one of the fields must be filled in.";
    String[] fieldNames();

    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    @Target({ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @Documented
    @interface List {
        OneOfFieldsNotBlank[] value();
    }

}