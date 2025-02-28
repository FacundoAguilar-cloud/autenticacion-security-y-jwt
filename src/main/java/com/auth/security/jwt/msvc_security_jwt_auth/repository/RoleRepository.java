package com.auth.security.jwt.msvc_security_jwt_auth.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.RoleEntity;
@Repository
public interface RoleRepository extends CrudRepository <RoleEntity, Long> {
List <RoleEntity> findRoleEntitiesByRoleEnumIn(List <String> roleNames); //si los roles que estan en la DB coinciden, los va a devolver, si no coinciden no. Con esto nos aseguramos que el rol siempre exista

}
