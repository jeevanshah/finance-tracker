package com.financetracker.service;

import com.financetracker.dto.UserDTO;
import com.financetracker.entity.User;
import org.springframework.stereotype.Service;


public interface JwtService {
    String generateToken(UserDTO user);
}
