package com.financetracker.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;

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
import java.util.Date;
import java.util.stream.Collectors;

@Service
public class JwtEncoderDecoder {

    @Value("${private-key}")
    private String privateKeyContent;
    @Value("${public-key}")
    private String publicKeyContent;

    public JwtEncoderDecoder() {
    }

    public String generateJwtToken() throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new RuntimeException("SecurityContext is not set properly or user is not authenticated.");
        }

        String username = authentication.getName();
        String roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // Build JWT claims
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(username)
                .issuer("self")
                .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000)) // Token valid for 1 hour
                .issueTime(new Date())
                .claim("roles", roles)
                .build();

        // Sign the JWT using RS256 algorithm
        JWSSigner signer = new RSASSASigner(loadPrivateKey());
        SignedJWT signedJWT = new SignedJWT(
                new com.nimbusds.jose.JWSHeader(JWSAlgorithm.RS256),
                claimsSet
        );
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private RSAPrivateKey loadPrivateKey() throws Exception {
        byte[] decodedPrivateKey = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
    @Bean
    public JwtDecoder jwtDecoder() throws Exception {
        RSAPublicKey publicKey = loadPublicKey();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    private RSAPublicKey loadPublicKey() throws Exception {
        //String publicKeyContent = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyoy6nNr3ylCQ6FHN85x5NOFCNK1Oo86oMiYHRnnhcjlJ+FQVdvT3rO5rVir9GajgCyhU1eJGGh+ZUli021ygZPf4kKRs3e4/ApkKE31HI0Xvsjcc9ZYb0R0IKhAVyZ/vSF+l8wnk7GIxUh3JwCxSIt9Yc/S2SMY7W2ki5QwWP1ZHcEKfLmguwawTcYcEEWz2NGeley7VlBKoJMdcY61YluA8v+gfmXJBucnT7407dRKzKSvDRDokyTts9UiAIF0FGrHbtmrMemuuL0fUaXiZN6CHrUA8ZEWHrbm1W/uaEYTUCyqFklbNd3t2noWkpKRweQWa4TI6BlCAts6geanFwwIDAQAB";
        byte[] decoded = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return (RSAPublicKey) publicKey;
    }
}
