package com.financetracker.util;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JwtVerifier {

    public static void main(String[] args) throws Exception {
        // Your public key in Base64 (use the one generated above)
        String publicKeyBase64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyoy6nNr3ylCQ6FHN85x5NOFCNK1Oo86oMiYHRnnhcjlJ+FQVdvT3rO5rVir9GajgCyhU1eJGGh+ZUli021ygZPf4kKRs3e4/ApkKE31HI0Xvsjcc9ZYb0R0IKhAVyZ/vSF+l8wnk7GIxUh3JwCxSIt9Yc/S2SMY7W2ki5QwWP1ZHcEKfLmguwawTcYcEEWz2NGeley7VlBKoJMdcY61YluA8v+gfmXJBucnT7407dRKzKSvDRDokyTts9UiAIF0FGrHbtmrMemuuL0fUaXiZN6CHrUA8ZEWHrbm1W/uaEYTUCyqFklbNd3t2noWkpKRweQWa4TI6BlCAts6geanFwwIDAQAB";

        // Decode the public key
        byte[] decodedPublicKey = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

        // The JWT token you want to verify
        String jwtToken = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzZWxmIiwic3ViIjoidGVzdHVzZXIiLCJleHAiOjE3MzU5MTc1NTcsImlhdCI6MTczNTkxMzk1Nywicm9sZXMiOiJST0xFX1VTRVIifQ.q2Ho7jgJ_Xj1yzTiE88x67luMkM0RT3GE8WXM7f4ae2QIzszfw2bf9THAoxWJ29RxxfUN4GtPB-MlPvH3wrZcjtdwipAqhFnbYGhzYAj4AcUtVcvZBSqcO8ONzzf7eYOI9z_Lemd_d_jh86L72VlelEjJxF4xPLdLtcBfyY-lAih6PQ_NVJ_1EE-1A7TYdfJd5afCp7-SWEKLBuY1DKxb4tu6wgEUaP4rXZ2P-v0aE_sfm_HJnJf-aZ_Uw7ycaMNWCLCbTSudqQzKOMwjGAwmnanhJ_AtTm11jYe3kB75gOUMM6tj5Yyrlxbuwm1Wih-ZX124hX0QJElLd_V481IdQ";
        // Parse the JWT token
        SignedJWT signedJWT = SignedJWT.parse(jwtToken);

        // Verify the signature
        RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
        if (signedJWT.verify(verifier)) {
            System.out.println("JWT signature is valid.");
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            System.out.println("Claims: " + claims);
        } else {
            System.out.println("Invalid JWT signature.");
        }
    }
}
