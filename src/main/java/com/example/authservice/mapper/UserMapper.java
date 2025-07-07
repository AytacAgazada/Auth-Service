package com.example.authservice.mapper;

import com.example.authservice.model.dto.SignupRequest;
import com.example.authservice.model.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserMapper {

    @Mapping(target = "password", ignore = true) // Parol mapper tərəfindən deyil, service tərəfindən şifrələnəcək
    User toEntity(SignupRequest signupRequest);
}