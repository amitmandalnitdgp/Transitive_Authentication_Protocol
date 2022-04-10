import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

//import org.apache.commons.codec.DecoderException;
import org.bouncycastle.util.encoders.Hex;

public class RC4Encryption {

	public static String encryptText(String plainText, String secKey) throws Exception {

		byte[] plainBytes = plainText.getBytes();
		String hashedKey = hashedData(secKey);
		Key key = new SecretKeySpec(Hex.decode(hashedKey), "RC4");
		Cipher cipher = Cipher.getInstance("RC4"); // Transformation of the algorithm
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		String encoded = encodeBase64(cipherBytes);
		return encoded;
	}

	public static String decryptText(String encoded, String secKey) throws Exception {

		String hashedKey = hashedData(secKey);
		Key key = new SecretKeySpec(Hex.decode(hashedKey), "RC4");
		Cipher cipher = Cipher.getInstance("RC4");
		cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
		String decoded = decodeBase64(encoded);
		byte[] plainBytesDecrypted = cipher.doFinal(Hex.decode(decoded));
		return new String(plainBytesDecrypted);

	}

	static String decryptRC4() throws Exception {

		byte[] plainBytes = "testString".getBytes();

		String hashedKey = hashedData("thisismysecretkey-123");

		// Generate a new key using KeyGenerator
		/*
		 * KeyGenerator rc4KeyGenerator = KeyGenerator.getInstance("RC4"); SecretKey key
		 * = rc4KeyGenerator.generateKey();
		 */

		Key key = new SecretKeySpec(Hex.decode(hashedKey), "RC4"); // String to key conversion using Hex.decode to
																	// convert to byte []

		// Create Cipher instance and initialize it to encrytion mode
		Cipher cipher = Cipher.getInstance("RC4"); // Transformation of the algorithm
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherBytes = cipher.doFinal(plainBytes);

		String encoded = encodeBase64(cipherBytes);

		String decoded = decodeBase64(encoded);

		// Reinitialize the Cipher to decryption mode
		cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
		byte[] plainBytesDecrypted = cipher.doFinal(Hex.decode(decoded));

		System.out.println("Decrypted Data : " + new String(plainBytesDecrypted));
		return new String(plainBytesDecrypted);
	}

	static String decodeBase64(String encodedData) {
		byte[] b = Base64.getDecoder().decode(encodedData);
		String decodedData = DatatypeConverter.printHexBinary(b);
		return decodedData;
	}

	static String encodeBase64(byte[] data) {
		byte[] b = Base64.getEncoder().encode(data);
		String encodedData = new String(b);
		/* String encodedData = DatatypeConverter.printHexBinary(b); */
		return encodedData;
	}

	static String hashedData(String key) throws NoSuchAlgorithmException {
		String password = key;

		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(password.getBytes());

		byte byteData[] = md.digest();

		// convert the byte to hex format method 1
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < byteData.length; i++) {
			sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
		}

		// convert the byte to hex format method 2
		StringBuffer hexString = new StringBuffer();
		for (int i = 0; i < byteData.length; i++) {
			String hex = Integer.toHexString(0xff & byteData[i]);
			if (hex.length() == 1)
				hexString.append('0');
			hexString.append(hex);
		}
		return hexString.toString();
	}

}