package com.auth.security.jwt.msvc_security_jwt_auth.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.UserEntity;
@Repository
public interface UserRepository extends CrudRepository <UserEntity, Long> {
//este método nos va a servir para traer los usuarios de la base de datos directamente con el servicio de UserDetails    
Optional <UserEntity> findUserEntityByUsername(String username);
}
