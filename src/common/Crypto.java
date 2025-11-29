package common;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Crypto {
    public static KeyPair getRsaKeyPar() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static SecretKey getAESKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // AES 128 bits
        return generator.generateKey();
    }

    public static byte[] encryptAES(Object data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(Utils.toByteArray(data));
    }

    public static Object decryptAES(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    public static byte[] decryptAESBytes(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    public static byte[] applyAuth(SecurePacket packet, PrivateKey privateKey) throws Exception {
        byte[] aesKeyBytes = Crypto.decryptRSA(packet.key(), privateKey);
        SecretKeySpec sessionKey = new SecretKeySpec(aesKeyBytes, "AES");

        return Crypto.decryptAESBytes(packet.data(), sessionKey);
    }

    public static PublicKey parsePublicKey(String keyString) throws Exception {
        String realKey = keyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(realKey);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(spec);
    }

    public static SecurePacket getSecured(Object data, PublicKey publicKey) throws Exception {
        SecretKey sessionKey = Crypto.getAESKey();

        byte[] encryptedKey = Crypto.encryptRSA(sessionKey.getEncoded(), publicKey);

        byte[] encryptedData = Crypto.encryptAES(data, sessionKey);

        return new SecurePacket(encryptedKey, encryptedData);
    }

}
