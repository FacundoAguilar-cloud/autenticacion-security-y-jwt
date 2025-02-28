package com.auth.security.jwt.msvc_security_jwt_auth.Util;

import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

@Component
public class JwtUtils {
@Value("${security.jwt.key.private}")
private String privateKey;
@Value("${security.jwt.user.generator}")
private String userGenerator;

//teniendo esto ya podemos empezar a generar los métodos para la creación del token como tal 
//esto que ponemos es un objeto de SP que nos va a permitir extraer el usuario y las autorizaciones

public String createToken(Authentication authentication){
//para encriptar primero definimos el algoritmo 
Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

String username = authentication.getPrincipal().toString();
//aca obtiene las autorizaciones y los mapea separados en coma 
String authorities = authentication.getAuthorities()
.stream()
.map(GrantedAuthority:: getAuthority)
.collect(Collectors.joining(","));

String jwtToken = JWT.create()
.withIssuer( this.userGenerator) 
// osea el sujeto/persona a la que se le va a generar el token 
.withSubject(username)
.withClaim("authorities", authorities)
.withIssuedAt(new Date())
.withExpiresAt(new Date(System.currentTimeMillis() + 1800000))
//con esto se le da un valor de ID random, por lo tanto cada token va a tener un ID al azar completamente distinto
.withJWTId(UUID.randomUUID().toString())
.withNotBefore(new Date(System.currentTimeMillis()))
.sign(algorithm);

return jwtToken;

//teniendo listo el método que se encarga de crear el token ahora debemos de hacer otro que se ocupe de validarlo 




}

public DecodedJWT validateToken(String token){
    try {
        Algorithm algorithm = Algorithm.HMAC256(this.privateKey);
        JWTVerifier verifier = JWT.require(algorithm)
        .withIssuer(userGenerator)
        .build();

       DecodedJWT decodedJWT = verifier.verify(token);

       return decodedJWT;

    } catch (JWTVerificationException exception) {
       throw new JWTVerificationException("invalid token, not Authorized. Please, try again");
    }
}

//ya realizado el método que se encarga de validar el token que creamos ahora necesitamos otro método que extraiga el nombre del usuario que viene dentro del token

public String extractUsername(DecodedJWT decodedJWT){
    return decodedJWT.getSubject().toString();
}

public Claim getSpecificClaim(DecodedJWT decodedJWT, String claimName){
    return decodedJWT.getClaim(claimName);
}
// aca tambien se puede usar un map tranquilamente
public  Claim getAllClaims(DecodedJWT decodedJWT){
    return (Claim) decodedJWT.getClaims();
    }
}
