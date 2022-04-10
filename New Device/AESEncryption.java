import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
 
public class AESEncryption {
    
    public static SecretKey generateAESkey (String strkey, int nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	String password = strkey;
        String salt = ""+nonce;
        int iterations = 100;
        int keyLength = 128;
        char[] passwordChars = password.toCharArray();
        byte[] saltBytes = salt.getBytes();
        SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
        PBEKeySpec spec = new PBEKeySpec( passwordChars, saltBytes, iterations, keyLength );
        SecretKey key = skf.generateSecret( spec );
        SecretKey secret = new SecretKeySpec(key.getEncoded(), "AES");
        return secret;
    }
     
    public static SecretKey getSecretEncryptionKey() throws Exception{
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        return secKey;
    }
     
    public static byte[] encryptText(String plainText,SecretKey secKey) throws Exception{
    // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return byteCipherText;
    }
     
    public static String decryptText(byte[] byteCipherText, SecretKey secKey) throws Exception {
    // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
        return new String(bytePlainText);
    }
     
    public static String  bytesToHex(byte[] hash) {
        return DatatypeConverter.printHexBinary(hash);
    }
}