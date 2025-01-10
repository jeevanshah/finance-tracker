package com.financetracker.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class KeyGenerator {

    public static void main(String[] args) throws Exception {
        // Generate an RSA Key Pair (private and public keys)
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);  // Key size
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Get the private key
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // Get the public key
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        // Print the private key as Base64 encoded string
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        System.out.println("Private Key: \n" + privateKeyBase64);

        // Print the public key as Base64 encoded string
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        System.out.println("\nPublic Key: \n" + publicKeyBase64);
    }
}
