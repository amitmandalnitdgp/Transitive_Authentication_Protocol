import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class TripleDES {

	private static SecretKeySpec secretKey;
	private static String ALGORITHM_NAME = "DESede";
	private static String MODE_OF_OPERATION = "ECB";
	private static String PADDING_SCHEME = "PKCS5Padding";
	private final static int TDES_KEYLENGTH = 24;

	public static void setKey(String secret) {
		try {
			byte[] key = secret.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			byte[] digestOfPassword = sha.digest(key);
			byte[] keyBytes = Arrays.copyOf(digestOfPassword, TDES_KEYLENGTH);
			secretKey = new SecretKeySpec(keyBytes, ALGORITHM_NAME);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	public static String encrypt(String strDataToEncrypt, String secret) {
		try {
			setKey(secret);
			Cipher desCipher = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);
			desCipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] byteDataToEncrypt = strDataToEncrypt.getBytes("UTF-8");
			byte[] byteCipherText = desCipher.doFinal(byteDataToEncrypt);
			byte[] base64EncryptedString = Base64.getEncoder().encode(byteCipherText);
			return new String(base64EncryptedString);
		} catch (Exception ex) {
			System.out.println("Error while encrypting: " + ex.toString());
		}
		return null;
	}

	public static String decrypt(String cipherText, String secret) {
		try {
			setKey(secret);
			Cipher desCipher = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);
			desCipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] byteCipherText = Base64.getDecoder().decode(cipherText.getBytes());
			byte[] byteDecryptedText = desCipher.doFinal(byteCipherText);
			return new String(byteDecryptedText, "UTF-8");
		} catch (Exception ex) {
			System.out.println("Error while decrypting: " + ex.toString());
		}
		return null;
	}
}