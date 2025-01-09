package com.financetracker.service.impl;

import com.financetracker.dto.UserDTO;
import com.financetracker.entity.User;
import com.financetracker.mapper.UserMapper;
import com.financetracker.repository.UserRepository;
import com.financetracker.service.UserService;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    public UserServiceImpl(UserRepository userRepository, UserMapper userMapper) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
    }

    @Override
    public UserDTO getUserByEmail(String username) {
        Optional<User> user = userRepository.findByEmail(username);
        return userMapper.toDto(userMapper.optionalToEntity(user));

    }

    @Override
    public UserDTO getUserByEmail(Long id) {
        return null;
    }
}
