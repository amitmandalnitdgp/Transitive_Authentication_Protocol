
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES {
	private final static int AES_KEYLENGTH = 128;
	private static SecretKeySpec secretKey;
	private static byte[] key;
	private static String ALGORITHM_NAME = "AES";
	private static String MODE_OF_OPERATION = "ECB"; /* ECB/CBC/CTR/GCM/CCM */
	private static String PADDING_SCHEME = "PKCS5Padding";
	private static final byte[] SALT = { (byte) 0x28, (byte) 0x5F, (byte) 0x71, (byte) 0xC9, (byte) 0x1E, (byte) 0x35,
			(byte) 0x0A, (byte) 0x62 };

	public static void setKey(String secret) {
		try {
			key = secret.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			sha.update(SALT);
			byte[] digestOfPassword = sha.digest(key);
			byte[] keyBytes = Arrays.copyOf(digestOfPassword, 32);
			secretKey = new SecretKeySpec(keyBytes, ALGORITHM_NAME);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	// Needed for CBC or CTR operation mode and pass to aesChipher.init()
	public static byte[] generateInitializationVector() {
		byte[] iv = new byte[AES_KEYLENGTH / 8];
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(iv);
		return iv;
	}

	public static String encrypt(String strDataToEncrypt, String secret) {
		try {
			setKey(secret);
			Cipher aesCipher = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);
			aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] byteDataToEncrypt = strDataToEncrypt.getBytes();
			byte[] byteCipherText = aesCipher.doFinal(byteDataToEncrypt);
			byte[] strCipherText = Base64.getEncoder().encode(byteCipherText);

			return new String(strCipherText);
		} catch (Exception ex) {
			System.out.println("Error while encrypting: " + ex.toString());
		}
		return null;
	}

	public static String decrypt(String cipherText, String secret) {
		try {
			setKey(secret);
			Cipher aesCipher = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);
			aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] byteCipherText = Base64.getDecoder().decode(cipherText.getBytes());

			byte[] byteDecryptedText = aesCipher.doFinal(byteCipherText);
			return new String(byteDecryptedText);
		} catch (Exception ex) {
			System.out.println("Error while decrypting: " + ex.toString());
		}
		return null;
	}
}