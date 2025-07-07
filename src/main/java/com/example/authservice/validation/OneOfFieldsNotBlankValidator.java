package com.example.authservice.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.BeanWrapperImpl; // Bu importu əlavə edin

public class OneOfFieldsNotBlankValidator implements ConstraintValidator<OneOfFieldsNotBlank, Object> {

    private String[] fieldNames;

    @Override
    public void initialize(OneOfFieldsNotBlank constraintAnnotation) {
        this.fieldNames = constraintAnnotation.fieldNames();
    }

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        if (value == null) {
            return true;
        }

        BeanWrapperImpl beanWrapper = new BeanWrapperImpl(value);
        boolean atLeastOneNotBlank = false;

        for (String fieldName : fieldNames) {
            Object fieldValue = beanWrapper.getPropertyValue(fieldName);
            if (fieldValue != null && !fieldValue.toString().trim().isEmpty()) {
                atLeastOneNotBlank = true;
                break;
            }
        }

        if (!atLeastOneNotBlank) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                    .addConstraintViolation();
            return false;
        }

        return true;
    }
}
