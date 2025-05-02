package com.SpringSecurity.spring_security.service;


import com.SpringSecurity.spring_security.dtos.UserDTO;
import com.SpringSecurity.spring_security.model.User;

import java.util.List;

public interface UserService {

    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    User findByUsername(String username);
}
