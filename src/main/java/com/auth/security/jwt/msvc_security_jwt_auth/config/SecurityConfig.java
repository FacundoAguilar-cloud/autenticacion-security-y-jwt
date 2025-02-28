package com.auth.security.jwt.msvc_security_jwt_auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth.security.jwt.msvc_security_jwt_auth.Util.JwtUtils;
import com.auth.security.jwt.msvc_security_jwt_auth.config.filter.JwtTokenValidator;
import com.auth.security.jwt.msvc_security_jwt_auth.services.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
@Autowired
private AuthenticationConfiguration authenticationConfiguration;

@SuppressWarnings("unused")
@Autowired
private UserDetailsServiceImpl userDetailsServiceImpl;

@Autowired
private JwtUtils jwtUtils;

@SuppressWarnings("unused")
@Autowired
private JwtTokenValidator jwtTokenValidator;

// este es el "contenedor" donde vamos a poner los filtros por donde van a pasar las peticiones.
@Bean
public SecurityFilterChain securityFilterChain (HttpSecurity httpSecurity) throws Exception{
    return httpSecurity
    .csrf(csrf -> csrf.disable())
    .httpBasic(Customizer.withDefaults())
    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .authorizeHttpRequests(http ->{
        //ENDPOINTS PÚBLICOS
        http.requestMatchers(HttpMethod.GET, "/test/hello").permitAll();
        //ENDPOINTS PRIVADOS 
        http.requestMatchers(HttpMethod.POST, "/test/post").hasAnyRole("ADMIN", "DEVELOPER");
        http.requestMatchers(HttpMethod.PATCH, "/test/patch").hasAnyAuthority("REFACTOR");
        
    })
    .addFilterBefore(new JwtTokenValidator(jwtUtils), BasicAuthenticationFilter.class) //acá iria el JwtTokenValidator, esa clase la tenemos que hacer nosotros y luego inyectarla.
    .build();
}
 //ahora necesitariamos armar un componente que maneje la autenticacion a partir de un objeto de Spring Security
 @Bean
 public AuthenticationManager authenticationManager() throws Exception{
     return authenticationConfiguration.getAuthenticationManager();
 }

 //proximo a esto vamos a usar un provider para autenticar, podemos usar el de la DB o en su defecto JWT auth.
 //tener en cuenta que este método va a necesitar un UserDetailsService que es la clase que hará la llamada a la DB desde el service y un passwordEncoder para manejar
//las contraseñas
 @Bean
 public AuthenticationProvider authenticationProvider(UserDetailsServiceImpl userDetailsServiceImpl){
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setPasswordEncoder(passwordEncoder());
    provider.setUserDetailsService(userDetailsServiceImpl);
    return provider;
 }
 //con esto vamos a poder encriptar la contraseña

@Bean
 public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
 }

}
