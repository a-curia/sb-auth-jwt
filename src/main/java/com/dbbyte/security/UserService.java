package com.dbbyte.security;

import java.util.Optional;

import com.dbbyte.entity.User;

/**
 * 
 */
public interface UserService {
    public Optional<User> getByUsername(String username);
}
