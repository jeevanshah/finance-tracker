package com.financetracker.service.impl;

import com.financetracker.dto.UserDTO;
import com.financetracker.entity.User;
import com.financetracker.mapper.UserMapper;
import com.financetracker.repository.UserRepository;
import com.financetracker.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, UserMapper userMapper, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDTO getUserByUsername(String username) {
        Optional<User> user = userRepository.findByUsername(username);
        return userMapper.toDto(userMapper.optionalToEntity(user));

    }

    @Override
    public UserDTO getUserByUsername(Long id) {
        return null;
    }

    public void registerUser(String username, String password, String roles) {
        String encodedPassword = passwordEncoder.encode(password);
        User user = new User();
        user.setUsername(username);
        user.setPassword(encodedPassword);
        user.setRoles(roles);
        userRepository.save(user);
    }
}
