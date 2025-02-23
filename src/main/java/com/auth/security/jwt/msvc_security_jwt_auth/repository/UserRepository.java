package com.auth.security.jwt.msvc_security_jwt_auth.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.UserEntity;
@Repository
public interface UserRepository extends CrudRepository <Long, UserEntity> {
Optional <UserEntity> findUserEntityByUsername(String username);
}
