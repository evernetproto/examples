package org.evernet;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Key {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Get the private public key pair in system
        KeyPair keyPair = Key.getKey();

        System.out.println("Private Key:");
        System.out.println(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

        System.out.println("Public Key:");
        System.out.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

    }

    protected static KeyPair getKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path directoryPath = Path.of(System.getProperty("user.home"), ".evernet", "keys");
        Files.createDirectories(directoryPath);

        Path privateKeyPath = Path.of(directoryPath.toString(), "private.key.1");
        Path publicKeyPath = Path.of(directoryPath.toString(), "public.key.1");

        if (Files.exists(privateKeyPath)) {
            System.out.println("Private key found");

            byte[] bytes = Files.readAllBytes(privateKeyPath);
            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(ks);

            bytes = Files.readAllBytes(publicKeyPath);
            X509EncodedKeySpec pubks = new X509EncodedKeySpec(bytes);
            kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(pubks);

            return new KeyPair(publicKey, privateKey);
        } else {
            System.out.println("Private key not found, generating new");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(4096);
            KeyPair pair = generator.generateKeyPair();
            try (FileOutputStream fos = new FileOutputStream(publicKeyPath.toFile())) {
                fos.write(pair.getPublic().getEncoded());
            }
            try (FileOutputStream fos = new FileOutputStream(privateKeyPath.toFile())) {
                fos.write(pair.getPrivate().getEncoded());
            }
            return pair;
        }
    }
}
