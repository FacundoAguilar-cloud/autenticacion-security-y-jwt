package com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto;

import java.util.List;

import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Size;
@Validated
public record AuthCreateRoleRequest(
    @Size(max =  3) List <String> roleListName) {

}
