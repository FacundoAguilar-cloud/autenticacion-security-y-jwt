package com.auth.security.jwt.msvc_security_jwt_auth.services;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.UserEntity;
import com.auth.security.jwt.msvc_security_jwt_auth.repository.UserRepository;
@Service
public class UserDetailsServiceImpl implements UserDetailsService{
    //este método basicamente se va a encargar de traer los usuarios directamente desde la DB
    @Autowired 
    private UserRepository userRepository;
    
    
    
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

}
