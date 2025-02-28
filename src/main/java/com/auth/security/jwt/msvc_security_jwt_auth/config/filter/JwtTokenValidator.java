package com.auth.security.jwt.msvc_security_jwt_auth.config.filter;

import java.io.IOException;
import java.util.Collection;

import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth.security.jwt.msvc_security_jwt_auth.Util.JwtUtils;
import com.auth0.jwt.interfaces.DecodedJWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtTokenValidator extends OncePerRequestFilter {
// con esto vamos a ejecutar un filtro por cada request que se haga
    
private JwtUtils jwtUtils;

public JwtTokenValidator(JwtUtils jwtUtils) {
    this.jwtUtils = jwtUtils;
}

@Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response, 
        @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        
      
        String jwtToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        //si el token viene vamos a trabajar con el y validarlo
        if (jwtToken!= null) {
            //teniendo en cuenta que el bearer no nos importa
            jwtToken= jwtToken.substring(7); //con esto lo que hacemos es cortar y sacarle directamente el bearer para tener unicamente el token
           DecodedJWT decodedJWT =  jwtUtils.validateToken(jwtToken);

           String username = jwtUtils.extractUsername(decodedJWT);
           //vamos a necesitar tener las autorizaciones, se las pedimos al utils y las convertimos a Strings  
           String stringAuthorities = jwtUtils.getSpecificClaim(decodedJWT, "authorities").asString();
            //convertimos los authorithies a una coleccion de grantedAuthority y utilizamos este metodo para que los separe por coma 
           Collection <? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(stringAuthorities);
           SecurityContext context = SecurityContextHolder.getContext();
            //declaramos el objeto auth para podeer establecerlo en el security context holder
           Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities );

           context.setAuthentication(authentication);

           SecurityContextHolder.setContext(context);
        } 
        filterChain.doFilter(request, response);
    }

}
