package com.auth.security.jwt.msvc_security_jwt_auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto.AuthCreateUser;
import com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto.AuthLoginRequest;
import com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto.AuthResponse;
import com.auth.security.jwt.msvc_security_jwt_auth.services.UserDetailsServiceImpl;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {
@Autowired
private UserDetailsServiceImpl userDetailsServiceImpl;

@PostMapping("/log-in")
public ResponseEntity <AuthResponse> login (@RequestBody @Valid AuthLoginRequest userRequest){
return new ResponseEntity<>(this.userDetailsServiceImpl.loginUser(userRequest), HttpStatus.OK);
}



@PostMapping("/sign-up")
public ResponseEntity <AuthResponse> register (@RequestBody @Valid AuthCreateUser authCreateUser) {
    
    return new ResponseEntity<>(this.userDetailsServiceImpl.createUser(authCreateUser), HttpStatus.CREATED);
}
}