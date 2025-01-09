package com.financetracker.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var user = User.withUsername("testuser")
                .password(passwordEncoder().encode("password123"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtEncoder jwtEncoder() throws Exception {
        RSAPrivateKey privateKey = loadPrivateKey();
        RSAPublicKey publicKey = loadPublicKey(privateKey);

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .build();

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }

    private RSAPublicKey loadPublicKey(RSAPrivateKey privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        BigInteger publicExponent = BigInteger.valueOf(65537);
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), publicExponent);
        return (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
    }

    private RSAPrivateKey loadPrivateKey() throws Exception {
        String privateKeyContent = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDKjLqc2vfKUJDoUc3znHk04UI0rU6jzqgyJgdGeeFyOUn4VBV29Pes7mtWKv0ZqOALKFTV4kYaH5lSWLTbXKBk9/iQpGzd7j8CmQoTfUcjRe+yNxz1lhvRHQgqEBXJn+9IX6XzCeTsYjFSHcnALFIi31hz9LZIxjtbaSLlDBY/VkdwQp8uaC7BrBNxhwQRbPY0Z6V7LtWUEqgkx1xjrViW4Dy/6B+ZckG5ydPvjTt1ErMpK8NEOiTJO2z1SIAgXQUasdu2asx6a64vR9RpeJk3oIetQDxkRYetubVb+5oRhNQLKoWSVs13e3aehaSkpHB5BZrhMjoGUIC2zqB5qcXDAgMBAAECggEAHjyu+Q6JMjcfwsa/h5AC2h2MjB+ZH0QRANeDe4ZjXPFndP5ca/M67CJ1fJoTSZrXw2Kkc3+BdpHkChJ7AUpNGXWZMkKRi/nuhx1Aj1NC5OWiWEj49kKP6YI7f0gCcKSDDJtWwzblaVJpSXhv71POeS09X6YW9js9jjJeRrIsugyLu8YK0xwpiImE2jMkx1KrAU61PcV3okGDJXmx8KRQDsJIfsU+l+fw/MaFFEzCSp0Ui/8B5QZ4beFsZidOCVBBYxOOuR1qTtMrff3bDr2EqLLhZoN7F8i+yscyrx8A7L9AlDxYyrshbNQpjpFZS47bXnBSjQLpiQlOyZSjBoa2/QKBgQDcIF1ss65Lqj72RCj1AZz9l1w+wXZ1I1gzZQg3xeIyV16hhmrNTs9lOl8pZNz+Z69wikaQRUhHOt0LHPR+REYvjCdtYFt5SGTuNNYym6Hpc5VD3mlylag8UGstlfHoq7bK6xO7vYBhxzvZktSuQo/GAiJSFz/ApL4UNtsm0zofPQKBgQDrjxEuNdR+ohFt7zWAVmKFaoLtuBD3RXVM7976D5JtpDmuWdM3cNafF6PetZsRQL4r61OFIbXknKV4IwqQ5VTX9Jdw5V7EvRoXfOn/JoqEvg0D843BOwohyQjWPRPUzrb8zR3xuF7V7PB9Kzlv+zdZ+0kLz+oCEC9mu6blaaHI/wKBgQCV21K+1fQqftQuQ2i+o0KFQa4C6yIBzPYWxwk5LvY231QFEsVSz/xRJdPzEj+A0oWVUA2J2iDCnUgucJ/h9gjyBbAxvg+IGcjcggvwmBM6Iv3THm8bGtdVeEn+1r3BcGUY78CXZwMnjcMo89TmbVoDqyBCUqGMPJtKl63KWLKQ4QKBgQCQs9NHAtRlciOo19CS5P4inRqO84qgi6+SMqxUCqrV5ZN1ckKZBR0ioAAPeJookBACpM4qs1msdToEwenktqxW+S7qsEx2KQBVO2v3THK9No6CReRntl/z/y4JhX2gNdgdFdf2PF8tpR7alWn0S2tmQEJQGknTOKQVxOKyfSBgewKBgQDNWWY1oRCgzgGWx2szVNWVUTIvw/91RFM6y5VDNcueEfOUrGD1CiZI2PCNiWl5xX7rPBtDnnwMDaRM9fXrFKkbcpdo5uTSXS2k4AG1M4QguL1V5X64sujNpLbiYWoQTE5z+hEpdPTeIWkudxWg5X7Hku7WtLVHAzNOpHwdTLrVgg==";
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(
                new java.math.BigInteger(1, privateKeyBytes),
                new java.math.BigInteger(1, privateKeyBytes)
        );
        return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }


}
