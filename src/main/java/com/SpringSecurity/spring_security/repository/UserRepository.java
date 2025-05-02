package com.SpringSecurity.spring_security.repository;

import com.SpringSecurity.spring_security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserName(String username);
    Boolean existsByEmail(String email);
    Boolean existsByUserName(String username);
}
