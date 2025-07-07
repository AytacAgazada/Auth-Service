package com.example.authservice.exception;

public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String field, String value) {
        super(String.format("User with this %s '%s' already exists.", field, value));
    }
}