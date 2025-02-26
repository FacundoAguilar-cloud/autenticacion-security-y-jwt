package com.auth.security.jwt.msvc_security_jwt_auth;

import java.util.List;
import java.util.Set;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.PermissionEntity;
import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.RoleEntity;
import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.RoleEnum;
import com.auth.security.jwt.msvc_security_jwt_auth.persistence.entity.UserEntity;
import com.auth.security.jwt.msvc_security_jwt_auth.repository.UserRepository;

@SpringBootApplication
public class MsvcSecurityJwtAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(MsvcSecurityJwtAuthApplication.class, args);
	}

	@Bean
	CommandLineRunner init(UserRepository userRepository){
		//acá vamos a crear tanto los permisos como tambien los roles
		return args ->{
			//PERMISOS
			PermissionEntity createPermission = PermissionEntity.builder()
			.name("CREATE")
			.build();

			PermissionEntity readPermission = PermissionEntity.builder()
			.name("READ")
			.build();

			PermissionEntity deletePermission = PermissionEntity.builder()
			.name("DELETE")
			.build();
			
			PermissionEntity updatePermission = PermissionEntity.builder()
			.name("UPDATE")
			.build();

			PermissionEntity refactorPermission = PermissionEntity.builder()
			.name("REFACTOR")
			.build();
			//ROLES
			
			RoleEntity adminRole = RoleEntity.builder()
			.roleEnum(RoleEnum.ADMIN)
			.permissionList(Set.of(createPermission, readPermission, deletePermission, updatePermission))
			.build();

			RoleEntity invitedRole = RoleEntity.builder()
			.roleEnum(RoleEnum.INVITED)
			.permissionList(Set.of(readPermission))
			.build();

			RoleEntity userRole = RoleEntity.builder()
			.roleEnum(RoleEnum.USER)
			.permissionList(Set.of(readPermission, createPermission))
			.build();

			RoleEntity developerRole = RoleEntity.builder()
			.permissionList(Set.of(readPermission,createPermission,deletePermission,updatePermission,refactorPermission))
			.build();

			//creados ya los permisos y los roles deberiamos crear los usuarios y guardarlos dentro del UserRepository.
			UserEntity userFacundo = UserEntity.builder()
		.username("facundo")	
		.password("1234asd")
		.isEnabled(true)
		.accountNoExpired(true)
		.accountNoLocked(true)
		.credentialNoExpired(true)
		.roles(Set.of(adminRole))
		.build();

		UserEntity userGabriel = UserEntity.builder()
		.username("gabriel")	
		.password("fgh123")
		.isEnabled(true)
		.accountNoExpired(true)
		.accountNoLocked(true)
		.credentialNoExpired(true)
		.roles(Set.of(userRole))
		.build();

		UserEntity userJuan = UserEntity.builder()
		.username("ivan")	
		.password("jkl123")
		.isEnabled(true)
		.accountNoExpired(true)
		.accountNoLocked(true)
		.credentialNoExpired(true)
		.roles(Set.of(invitedRole))
		.build();

		UserEntity userIvan = UserEntity.builder()
		.username("ivan")	
		.password("zxc123")
		.isEnabled(true)
		.accountNoExpired(true)
		.accountNoLocked(true)
		.credentialNoExpired(true)
		.roles(Set.of(developerRole))
		.build();

		userRepository.saveAll(List.of(userFacundo, userGabriel, userIvan, userJuan));
	};
}
}



