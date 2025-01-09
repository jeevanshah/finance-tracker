package com.financetracker.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Base64;

public class JwtSigner {

    public static void main(String[] args) throws Exception {
        // Your private key in Base64 (use the one generated above)
        String privateKeyBase64 = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDKjLqc2vfKUJDoUc3znHk04UI0rU6jzqgyJgdGeeFyOUn4VBV29Pes7mtWKv0ZqOALKFTV4kYaH5lSWLTbXKBk9/iQpGzd7j8CmQoTfUcjRe+yNxz1lhvRHQgqEBXJn+9IX6XzCeTsYjFSHcnALFIi31hz9LZIxjtbaSLlDBY/VkdwQp8uaC7BrBNxhwQRbPY0Z6V7LtWUEqgkx1xjrViW4Dy/6B+ZckG5ydPvjTt1ErMpK8NEOiTJO2z1SIAgXQUasdu2asx6a64vR9RpeJk3oIetQDxkRYetubVb+5oRhNQLKoWSVs13e3aehaSkpHB5BZrhMjoGUIC2zqB5qcXDAgMBAAECggEAHjyu+Q6JMjcfwsa/h5AC2h2MjB+ZH0QRANeDe4ZjXPFndP5ca/M67CJ1fJoTSZrXw2Kkc3+BdpHkChJ7AUpNGXWZMkKRi/nuhx1Aj1NC5OWiWEj49kKP6YI7f0gCcKSDDJtWwzblaVJpSXhv71POeS09X6YW9js9jjJeRrIsugyLu8YK0xwpiImE2jMkx1KrAU61PcV3okGDJXmx8KRQDsJIfsU+l+fw/MaFFEzCSp0Ui/8B5QZ4beFsZidOCVBBYxOOuR1qTtMrff3bDr2EqLLhZoN7F8i+yscyrx8A7L9AlDxYyrshbNQpjpFZS47bXnBSjQLpiQlOyZSjBoa2/QKBgQDcIF1ss65Lqj72RCj1AZz9l1w+wXZ1I1gzZQg3xeIyV16hhmrNTs9lOl8pZNz+Z69wikaQRUhHOt0LHPR+REYvjCdtYFt5SGTuNNYym6Hpc5VD3mlylag8UGstlfHoq7bK6xO7vYBhxzvZktSuQo/GAiJSFz/ApL4UNtsm0zofPQKBgQDrjxEuNdR+ohFt7zWAVmKFaoLtuBD3RXVM7976D5JtpDmuWdM3cNafF6PetZsRQL4r61OFIbXknKV4IwqQ5VTX9Jdw5V7EvRoXfOn/JoqEvg0D843BOwohyQjWPRPUzrb8zR3xuF7V7PB9Kzlv+zdZ+0kLz+oCEC9mu6blaaHI/wKBgQCV21K+1fQqftQuQ2i+o0KFQa4C6yIBzPYWxwk5LvY231QFEsVSz/xRJdPzEj+A0oWVUA2J2iDCnUgucJ/h9gjyBbAxvg+IGcjcggvwmBM6Iv3THm8bGtdVeEn+1r3BcGUY78CXZwMnjcMo89TmbVoDqyBCUqGMPJtKl63KWLKQ4QKBgQCQs9NHAtRlciOo19CS5P4inRqO84qgi6+SMqxUCqrV5ZN1ckKZBR0ioAAPeJookBACpM4qs1msdToEwenktqxW+S7qsEx2KQBVO2v3THK9No6CReRntl/z/y4JhX2gNdgdFdf2PF8tpR7alWn0S2tmQEJQGknTOKQVxOKyfSBgewKBgQDNWWY1oRCgzgGWx2szVNWVUTIvw/91RFM6y5VDNcueEfOUrGD1CiZI2PCNiWl5xX7rPBtDnnwMDaRM9fXrFKkbcpdo5uTSXS2k4AG1M4QguL1V5X64sujNpLbiYWoQTE5z+hEpdPTeIWkudxWg5X7Hku7WtLVHAzNOpHwdTLrVgg==";

        // Decode the private key
        byte[] decodedPrivateKey = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        // Create JWT Claims
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer("self")
                .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour
                .issueTime(new Date())
                .claim("roles", "ROLE_USER")
                .build();

        // Sign JWT
        SignedJWT signedJWT = new SignedJWT(
                new com.nimbusds.jose.JWSHeader(com.nimbusds.jose.JWSAlgorithm.RS256),
                claimsSet
        );

        RSASSASigner signer = new RSASSASigner(privateKey);
        signedJWT.sign(signer);

        // Get the signed token
        String jwtToken = signedJWT.serialize();
        System.out.println("Signed JWT Token: " + jwtToken);
    }
}
