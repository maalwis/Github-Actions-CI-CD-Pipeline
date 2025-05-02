package com.SpringSecurity.spring_security.repository;

import java.util.Optional;

import com.SpringSecurity.spring_security.model.AppRole;
import com.SpringSecurity.spring_security.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);

}
