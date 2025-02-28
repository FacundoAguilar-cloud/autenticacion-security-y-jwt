package com.auth.security.jwt.msvc_security_jwt_auth.services;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth.security.jwt.msvc_security_jwt_auth.Util.JwtUtils;
import com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto.AuthCreateUser;
import com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto.AuthLoginRequest;
import com.auth.security.jwt.msvc_security_jwt_auth.controller.Dto.AuthResponse;
import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.RoleEntity;
import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.UserEntity;
import com.auth.security.jwt.msvc_security_jwt_auth.repository.RoleRepository;
import com.auth.security.jwt.msvc_security_jwt_auth.repository.UserRepository;
@Service
public class UserDetailsServiceImpl implements UserDetailsService{
    //este método basicamente se va a encargar de traer los usuarios directamente desde la DB
    @Autowired 
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoleRepository roleRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
      UserEntity userEntity = userRepository.findUserEntityByUsername(username)
      .orElseThrow(()-> new UsernameNotFoundException("el usuario" + username + "no existe, vuelva a intentar por favor"));
      //ahora lo que deberiamos hacer es pasar los usuarios, las contraseñas y los permisos con su acceso a los roles
      
      List <SimpleGrantedAuthority> authorityList = new ArrayList<>();
      userEntity.getRoles()
      //aca tomamos los roles del usuario y lo que hacemos es recorrerlos y convertirlos a un SGA, o sea, un objeto de que entiende Spring Security
      .forEach(role -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name())))); 
        //habiendo agregado los roles ahora tenemos que agregar los permisos 
      userEntity.getRoles().stream()
      //como cada rol tiene que volver a recorrer cada permiso utilizamos el flatMap
      .flatMap(role -> role.getPermissionList().stream())
      .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getName())));
      
      
      
      //con esto le estamos diciendo a SP que busque los usuarios en los DB, que tome permisos y roles y los convierta a objetos que SP entiende y le devolvemos
      //el usuario  
      return new User(userEntity.getUsername(),
      userEntity.getPassword(),
      userEntity.isEnabled(),
      userEntity.isAccountNoExpired(),
      userEntity.isCredentialNoExpired(),
      userEntity.isAccountNoLocked(),
      authorityList
      );
    }


    public AuthResponse loginUser (AuthLoginRequest authLoginRequest){
      String username = authLoginRequest.username();
      String password = authLoginRequest.password();

      Authentication authentication = this.authenticate(username, password);

      SecurityContextHolder.getContext().setAuthentication(authentication);

      String accessToken = jwtUtils.createToken(authentication);

     AuthResponse authResponse = new AuthResponse(username, "User logged succesfully", accessToken, true);

     return authResponse;
    }



    public Authentication authenticate (String username, String password){
      UserDetails userDetails = this.loadUserByUsername(username);

      if (userDetails ==null) {
        throw new BadCredentialsException("invalid username or password, please try again");
      }
      if(!passwordEncoder.matches(password, userDetails.getPassword())){
        throw new BadCredentialsException("Invalid password");
      }
      return new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
    }


    public AuthResponse createUser (AuthCreateUser authCreateUser){
      String username = authCreateUser.username();
      String password = authCreateUser.password();
      //los roles que quiero sean asignados al usuario que se está registrando 
      List <String> roleRequest = authCreateUser.roleRequest().roleListName();
      //es una lista asi que lo transformamos en un set para que sean datos únicos, aca van a estar los roles que estan en la DB
      Set <RoleEntity> roleEntitySet = roleRepository.findRoleEntitiesByRoleEnumIn(roleRequest).stream().collect(Collectors.toSet());
      if (roleEntitySet.isEmpty()) {
        throw new IllegalArgumentException("The specifed roles doesnt exist.");
      }
      UserEntity userEntity = UserEntity.builder()
      .username(username)
      .password(passwordEncoder.encode(password))
      .roles(roleEntitySet)
      .isEnabled(true)
      .accountNoLocked(true)
      .accountNoExpired(false)
      .credentialNoExpired(false)
      .build();
     UserEntity userCreated = userRepository.save(userEntity);

     List <SimpleGrantedAuthority> authList = new ArrayList<>();
     userCreated.getRoles().forEach(role -> authList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));

     userCreated.getRoles().stream()
     .flatMap(role -> role.getPermissionList().stream())
     .forEach(permission -> authList.add(new SimpleGrantedAuthority(permission.getName())));
      
     Authentication authentication = new UsernamePasswordAuthenticationToken(userCreated.getUsername(), userCreated.getPassword(), authList);

     String accessToken = jwtUtils.createToken(authentication);

     AuthResponse authResponse = new AuthResponse(userCreated.getUsername(), "user created succesfully", accessToken, true);

     return authResponse;
    }

}
