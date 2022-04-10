
import java.security.spec.AlgorithmParameterSpec;

import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.util.Base64;
//import com.sun.mail.util.BASE64DecoderStream;
//import com.sun.mail.util.BASE64EncoderStream;

public class DESEncryption {

	private static Cipher ecipher;
	private static Cipher dcipher;

	private static final int iterationCount = 10;

	// 8-byte Salt
	private static byte[] salt = {

			(byte)0xB2, (byte)0x12, (byte)0xD5, (byte)0xB2,

			(byte)0x44, (byte)0x21, (byte)0xC3, (byte)0xC3
	};


	public static String encrypt(String str, String passPhrase) throws Exception {
		
		KeySpec keySpec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount);
		SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
		AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
		ecipher = Cipher.getInstance(key.getAlgorithm());
		ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

		try {

			// encode the string into a sequence of bytes using the named charset

			// storing the result into a new byte array. 

			byte[] utf8 = str.getBytes("UTF8");

			byte[] enc = ecipher.doFinal(utf8);

			//Base64.Encoder bsencoder; 
			// encode to base64

			enc = Base64.getEncoder().encode(enc);

			return new String(enc);

		}

		catch (Exception e) {

			e.printStackTrace();

		}

		return null;

	}

	public static String decrypt(String str, String passPhrase) throws Exception{
		
		KeySpec keySpec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount);
		SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
		AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
		dcipher = Cipher.getInstance(key.getAlgorithm());
		dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
		
		try {

			// decode with base64 to get bytes

			byte[] dec = Base64.getDecoder().decode(str.getBytes());

			byte[] utf8 = dcipher.doFinal(dec);

			// create new string based on the specified charset

			return new String(utf8, "UTF8");

		}

		catch (Exception e) {

			e.printStackTrace();

		}

		return null;

	}

}