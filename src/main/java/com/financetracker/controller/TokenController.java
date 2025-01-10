package com.financetracker.controller;

import com.financetracker.dto.UserDTO;
import com.financetracker.entity.User;
import com.financetracker.service.impl.JwtServiceImpl;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;

import java.util.Map;

@RestController
public class TokenController {

    private final JwtServiceImpl jwtService;

    public TokenController(JwtServiceImpl jwtService) {
        this.jwtService = jwtService;
    }


    @PostMapping("/token")
    public ResponseEntity<?> getToken(@RequestBody UserDTO user) {
        if (user.getUsername() == null || user.getUsername().isEmpty() ||
                user.getPassword() == null || user.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Email and password must not be empty"
            ));
        }

        try {
            String jwtToken = jwtService.generateToken(user);
            System.out.println("Signed JWT Token: " + jwtToken);

            // Return the generated JWT token
            return ResponseEntity.ok(Map.of("access_token", jwtToken));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "Invalid credentials",
                    "message", e.getMessage()
            ));
        }
    }
}
