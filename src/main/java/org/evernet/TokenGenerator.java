package org.evernet;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.util.UUID;

public class TokenGenerator {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Scanner scanner = new Scanner(System.in);

        // Read the entity identifier
        System.out.println("Enter entity identifier: ");
        String entityIdentifier = scanner.next();

        // Read the audience node
        System.out.println("Enter audience node: ");
        String audienceNode = scanner.next();

        // Read the key host node
        System.out.println("Enter key host node: ");
        String keyNode = scanner.next();

        // Get the private public key pair in system
        KeyPair keyPair = Key.getKey();
        PrivateKey privateKey = keyPair.getPrivate();

        // Generate token
        String token = Jwts.builder().setAudience(audienceNode).setSubject(entityIdentifier).setId(UUID.randomUUID().toString()).setHeaderParam("kid", entityIdentifier + "@" + keyNode).signWith(SignatureAlgorithm.RS512, privateKey).compact();

        // Print token
        System.out.println("Token:");
        System.out.println(token);
    }
}
