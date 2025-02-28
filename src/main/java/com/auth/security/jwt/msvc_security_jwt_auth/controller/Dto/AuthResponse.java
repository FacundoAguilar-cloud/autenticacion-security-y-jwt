package com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
//le damos un orden establecido con esta notacion
@JsonPropertyOrder({"username", "message", "jwt", "status"})
public record AuthResponse(
String username,
String message,
String jwt,
boolean status) {

}
