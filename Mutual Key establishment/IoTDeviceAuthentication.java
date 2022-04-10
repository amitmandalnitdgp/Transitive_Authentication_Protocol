import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;

import javax.crypto.SecretKey;

public class IoTDeviceAuthentication {

	public int Di, PW, Rd, T, PID, PIN;
	public String com1;

	public static double acosh(double x)
	{
		return Math.log(x + Math.sqrt(x*x - 1.0));
	}

	public static double chebyshev(double x, int z, int n) {
		return Math.cosh(n*acosh(x)%z);
	}

	public static String XOREncode(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < key.length(); i++)
			sb.append((char)(st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		str = str + st.substring(key.length());
		//System.out.println(st.substring(key.length()));
		return str;
	}

	public static String XORDecodekey(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < key.length(); i++)
			sb.append((char)(st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		return str;
	}

	public static String XORDecodeString(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < key.length(); i++)
			sb.append((char)(st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		str = str + st.substring(key.length());
		return str;
	}

	public static String getSha256(String str) {
		MessageDigest digest;
		String encoded = null;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
			encoded = Base64.getEncoder().encodeToString(hash);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return encoded;
	} 

	public static void main(String[] args) throws Exception {

		final String HOST = "127.0.0.1";
		final int PORT = 4080;

		Socket socket = new Socket(HOST, PORT);
		DataInputStream indata=new DataInputStream(socket.getInputStream());  
		DataOutputStream outdata=new DataOutputStream(socket.getOutputStream());  
		BufferedReader brk=new BufferedReader(new InputStreamReader(System.in)); 

		while (true) {
			//System.out.print("Input: ");
			String input=brk.readLine();//keyboard input

			if (input.equalsIgnoreCase("exit")) {
				outdata.writeUTF(input);
				outdata.flush();
				break;
			}
			long startTime = 0, estimatedTime = 0, time = 0;
			startTime = System.currentTimeMillis(); //start time
			long startTime_1 = System.currentTimeMillis(); //start time

			File file = new File("store.txt");
			BufferedReader br = new BufferedReader(new FileReader(file));
			String storetemp = br.readLine();
			String[] storeRead = storetemp.split("-");
			String Vstore = storeRead[0];
			int Xstore = Integer.parseInt(storeRead[1]);
			Double Tsstore = Double.parseDouble(storeRead[2]);
			Random rnd = new SecureRandom();
			int Nonce = BigInteger.probablePrime(15, rnd).intValue();

			//System.out.println("read: " + Vstore + "  X: "+Xstore+ "  Ts:" + Tsstore);

			int DID = 100301;//Integer.parseInt(reader.readLine());
			int PWD = 1234;//Integer.parseInt(reader.readLine());

			String sha2 = getSha256(Integer.toString(DID^PWD));
			//System.out.println("sha2: " + sha2 );

			String Zstr = XORDecodekey(Vstore, sha2);
			int Zstore = Integer.parseInt(Zstr.trim());
			//System.out.println("Zstore: " + Zstore );

			String zstr = XOREncode(""+Tsstore, ""+Zstore);
			String sha3 = getSha256(zstr);

			Random rand = new Random();
			int low = 10;
			int high = 100;
			int r = rand.nextInt(high-low) + low;
			double Tr = chebyshev(Xstore, Zstore, r);
			double Trs = chebyshev(Tsstore, Zstore, r);
			int k = (int)Trs;
			//System.out.println("Tsr: " + Trs +"  K: "+k);
			String encrypt = sha3+"-"+Nonce;

			try {
				// AES Encryption --------------------------------------------------------------------
				String cipherText = AES.encrypt(encrypt, ""+k);
				//-------------------------------------------------------------------------------------

				// DES Encryption ---------------------------------------------------------------------
				//String cipherText = DESEncryption.encrypt(encrypt, ""+k);
				//-------------------------------------------------------------------------------------
				
				// Triple DES Encryption ---------------------------------------------------------------------
				//String cipherText = TripleDES.encrypt(encrypt, ""+k);
				//-------------------------------------------------------------------------------------

				// RC4 Encryption ---------------------------------------------------------------------				
				//String cipherText = RC4Encryption.encryptText(encrypt, ""+k);
				//-------------------------------------------------------------------------------------

				// RC5 Encryption ---------------------------------------------------------------------				
				//String cipherText = RC5.encrypt(encrypt, ""+k);
				//-------------------------------------------------------------------------------------

				// RC6 Encryption ---------------------------------------------------------------------				
				//String cipherText = RC6.encrypt(encrypt, ""+k);
				//-------------------------------------------------------------------------------------

				System.out.println("plaintext:"+ encrypt);
				System.out.println("cipherText:"+cipherText);
				//System.out.println("-->> VP:"+ sha3);
				//System.out.println("-->> Nonce: " +Nonce);

				estimatedTime = System.currentTimeMillis() - startTime;
				time = time+ estimatedTime;

				outdata.writeUTF(cipherText+"-"+Tr);
				outdata.flush();

				String instr = indata.readUTF();

				startTime = System.currentTimeMillis(); //start time

				//System.out.println("Packet received: "+instr);
				String sha4 = getSha256(""+Nonce);
				//System.out.println("calculated hashed nonce: "+sha4);
				if(!instr.equals(sha4)) {
					System.out.println("Packet dropptd.......");
					break;
				}
				String sessionKey = getSha256(""+Nonce+k);
				System.out.println("-->> Session Key: " +sessionKey +"\n");

			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			estimatedTime = System.currentTimeMillis() - startTime;
			time = time+ estimatedTime;

			long estimatedTime_1 = System.currentTimeMillis() - startTime_1;
			System.out.println("estimatedTime (with comm. delay): " + estimatedTime_1);
			System.out.println("estimatedTime (without comm. delay): " + time);
		}

	}

}
