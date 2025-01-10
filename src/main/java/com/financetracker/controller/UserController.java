package com.financetracker.controller;

import com.financetracker.dto.UserDTO;
import com.financetracker.entity.User;
import com.financetracker.service.impl.JwtServiceImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class UserController {

    private final JwtServiceImpl jwtService;

    public UserController(JwtServiceImpl jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
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

    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getProfile(@RequestHeader(name = "Authorization", required = false) String authHeader) {
        // Check for the Authorization header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(Map.of("error", "Token is missing or invalid"));
        }

        // Extract the token (Remove "Bearer " prefix)
        String token = authHeader.substring(7);

        // Retrieve the currently authenticated user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "User not authenticated"));
        }

        // Extract user details
        String username = authentication.getName();
        var roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        // Build the response
        Map<String, Object> profile = new HashMap<>();
        profile.put("username", username);
        profile.put("roles", roles);
        profile.put("token", token); // Include the token in the response

        return ResponseEntity.ok(profile);
    }
}
