package com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto;

import jakarta.validation.constraints.NotBlank;

public record AuthLoginRequest(
@NotBlank String username,
@NotBlank String password    
) {

}
