//package com.financetracker.restController;
//
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//import java.time.Instant;
//import java.util.HashMap;
//import java.util.Map;
//
//@RestController
//
//public class ProfileController {
//
//    @GetMapping
//    public ResponseEntity<Map<String, Object>> getProfile() {
//        // Retrieve the currently authenticated user
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        String username = authentication.getName();
//        var roles = authentication.getAuthorities();
//
//        // Build the response data
//        Map<String, Object> data = new HashMap<>();
//        data.put("username", username);
//        data.put("roles", roles);
//
//        // Build the final response
//        Map<String, Object> response = new HashMap<>();
//        response.put("data", data);
//        response.put("status", "success");
//        response.put("message", "Profile fetched successfully");
//        response.put("timestamp", Instant.now().toString());
//
//        return ResponseEntity.ok(response);
//    }
//}
