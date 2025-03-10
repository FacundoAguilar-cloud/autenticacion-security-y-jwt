package com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

public record AuthCreateUser(
   @NotBlank String username,
   @NotBlank String password,
   @Valid AuthCreateRoleRequest roleRequest) {


}
