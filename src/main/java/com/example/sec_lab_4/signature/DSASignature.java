package com.example.sec_lab_4.signature;

import lombok.SneakyThrows;

import java.security.*;

public class DSASignature {
    private final Signature signature;
    private static final String SIGNATURE_ALGORITHM = "SHA1withDSA";


    @SneakyThrows
    public DSASignature() {
        signature = Signature.getInstance(SIGNATURE_ALGORITHM);
    }

    @SneakyThrows
    public byte[] sign(PrivateKey privateKey, byte[] data) {
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }


    public boolean verify(PublicKey publicKey, byte[] data, byte[] sign) {
        try {
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(sign);
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }


}
