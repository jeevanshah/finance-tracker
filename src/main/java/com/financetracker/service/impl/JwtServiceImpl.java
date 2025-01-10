package com.financetracker.service.impl;

import com.financetracker.config.JwtEncoderDecoder;
import com.financetracker.dto.UserDTO;
import com.financetracker.service.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class JwtServiceImpl implements JwtService {

    private final AuthenticationManager authenticationManager;
    private final JwtEncoderDecoder encoderDecoder;

    private final AuthenticationProviderImpl authenticationProvider;

    public JwtServiceImpl(AuthenticationManager authenticationManager, JwtEncoderDecoder encoderDecoder, AuthenticationProviderImpl authenticationProvider) {
        this.authenticationManager = authenticationManager;
        this.encoderDecoder = encoderDecoder;
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public String generateToken(UserDTO user) {
        String jwtToken = "";
        try {
            // Authenticate the user
            String username = user.getUsername();
            String password = user.getPassword();
            Authentication authentication = authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            SecurityContextHolder.getContext().setAuthentication(authentication);
           jwtToken = encoderDecoder.generateJwtToken();
            return jwtToken;
        } catch (Exception e) {
            System.out.println("e = " + e);
        }
        return jwtToken;
    }
}
