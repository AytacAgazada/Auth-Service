package com.example.authservice.model.dto;

import com.example.authservice.model.enumeration.Role;
import lombok.Data;

@Data
public class UserResponseDTO {

    private Long id;

    private String username;

    private String fin;

    private String email;

    private String phone;

    private Role role;
}
