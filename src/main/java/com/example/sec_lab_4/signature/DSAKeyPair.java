package com.example.sec_lab_4.signature;

import lombok.SneakyThrows;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DSAKeyPair {

    private static final String KEY_ALGORITHM = "DSA";
    private static final int KEY_SIZE = 1024;
    private static final Base64.Decoder BASE_64_DECODER = Base64.getDecoder();

    private final DSAPublicKey publicKey;
    private final DSAPrivateKey privateKey;
    private final Base64.Encoder BASE_64_ENCODER = Base64.getEncoder();

    @SneakyThrows
    private DSAKeyPair() {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        generator.initialize(KEY_SIZE);
        KeyPair keyPair = generator.generateKeyPair();
        this.publicKey = (DSAPublicKey) keyPair.getPublic();
        this.privateKey = (DSAPrivateKey) keyPair.getPrivate();
    }

    private DSAKeyPair(DSAPublicKey publicKey, DSAPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public static DSAKeyPair getInstance() {
        return new DSAKeyPair();
    }

    public DSAPublicKey getPublicKey() {
        return publicKey;
    }

    public DSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    @SneakyThrows
    public static DSAKeyPair read(File privateKeyFile, File publicKeyFile) {
        if (!privateKeyFile.exists() || !publicKeyFile.exists()) {
            DSAKeyPair keyPair = new DSAKeyPair();
            keyPair.save(privateKeyFile, publicKeyFile);
            return keyPair;
        }
        DSAPrivateKey privateKey;
        DSAPublicKey publicKey;
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        try (FileInputStream privateInputStream = new FileInputStream(privateKeyFile);
             FileInputStream publicInputStream = new FileInputStream(publicKeyFile)) {
            privateKey =
                    (DSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(
                            BASE_64_DECODER.decode(privateInputStream.readAllBytes())));
            publicKey =
                    (DSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(
                    BASE_64_DECODER.decode(publicInputStream.readAllBytes())));
            return new DSAKeyPair(publicKey, privateKey);
        } catch (IOException e) {
            e.printStackTrace();
            DSAKeyPair keyPair = new DSAKeyPair();
            keyPair.save(privateKeyFile, publicKeyFile);
            return keyPair;
        }
    }

    public void save(File privateKeyFile, File publicKeyFile) {
        try (FileOutputStream privateOutput = new FileOutputStream(privateKeyFile);
             FileOutputStream publicOutput = new FileOutputStream(publicKeyFile)) {
            privateOutput.write(BASE_64_ENCODER.encode(privateKey.getEncoded()));
            publicOutput.write(BASE_64_ENCODER.encode(publicKey.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
