package com.financetracker.restController;

import com.financetracker.model.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class UserController {

    @PostMapping("/login")
    public String test(@RequestBody User user) {
        System.out.println("user.getEmail() = " + user.getEmail());
        System.out.println("user.getEmail() = " + user.getPassword());
        return "Backend is working!";
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
