package com.financetracker.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class WebConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**") // Apply to all endpoints
                        .allowedOriginPatterns("*") // Allow all origins (temporary for debugging)
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true);
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder() throws Exception {
        RSAPublicKey publicKey = loadPublicKey();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    private RSAPublicKey loadPublicKey() throws Exception {
        String publicKeyContent = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyoy6nNr3ylCQ6FHN85x5NOFCNK1Oo86oMiYHRnnhcjlJ+FQVdvT3rO5rVir9GajgCyhU1eJGGh+ZUli021ygZPf4kKRs3e4/ApkKE31HI0Xvsjcc9ZYb0R0IKhAVyZ/vSF+l8wnk7GIxUh3JwCxSIt9Yc/S2SMY7W2ki5QwWP1ZHcEKfLmguwawTcYcEEWz2NGeley7VlBKoJMdcY61YluA8v+gfmXJBucnT7407dRKzKSvDRDokyTts9UiAIF0FGrHbtmrMemuuL0fUaXiZN6CHrUA8ZEWHrbm1W/uaEYTUCyqFklbNd3t2noWkpKRweQWa4TI6BlCAts6geanFwwIDAQAB";
        byte[] decoded = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return (RSAPublicKey) publicKey;
    }
}
