package com.auth.security.jwt.msvc_security_jwt_auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;



//ya activada la depen de SP se activan los filtros y no nos deja hacer la peticion, nos desautoriza automaticamente. 
//Tener en cuenta que tenemos un usuario y contraseña por defecto
@RestController
@RequestMapping("/test")
public class AuthControllerTest {
@GetMapping("/hello")
public String hello(){
    return "Hola";
}

@PostMapping("/post")
public String securedHello() {
    return "Hola posteado correctamente";
}

@PatchMapping("/patch")
public String patchear() {
    return "se ha parcheado correctamente";
}



}
