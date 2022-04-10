import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKey;

public class TransitiveGatewayAuthentication {

	public static double acosh(double x) {
		return Math.log(x + Math.sqrt(x * x - 1.0));
	}

	public static double chebyshev(double x, int z, int n) {
		return Math.cosh(n * acosh(x) % z);
	}

	public static String XOREncode(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < key.length(); i++)
			sb.append((char) (st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		str = str + st.substring(key.length());
		// System.out.println(st.substring(key.length()));
		return str;
	}

	public static String XORDecodekey(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < key.length(); i++)
			sb.append((char) (st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		return str;
	}

	public static String XORDecodeString(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < key.length(); i++)
			sb.append((char) (st.charAt(i) ^ key.charAt(i)));
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

	public static void main(String[] args) throws IOException {
		
		final int PORT = 4086;
		String SKt = "xs24h1wXGV/QgzARB1fPAgmv4s3yEPcIDwhnCxqxuIy9a0ATYE/g5+vVxCTZqnK0/R0JLGjR/+x0D91+i+72Uw";
		int sendSize = -1, receivedSize=-1;
		ServerSocket serverSocket = new ServerSocket(PORT);
		Socket clientSocket = serverSocket.accept();
		DataInputStream din = new DataInputStream(clientSocket.getInputStream());
		DataOutputStream dout = new DataOutputStream(clientSocket.getOutputStream());
		
		/*         PING TESTING
		 * System.out.println("Ping received from: "+din.readUTF());
		 * System.out.println("Ping sent to Trusted Device"); dout.writeUTF("Gateway");
		 * // send to trusted device dout.flush();
		 */
		
		
		
		String input = "", str2 = "";
		while (!input.equals("stop")) {
			
			////////////////receives from trusted device //////////////////////
			input = din.readUTF();
			//System.out.println("Received at GW: "+ input);
			
			if (input.equalsIgnoreCase("stop")) {
				break;
			}else {
				
				////////////////sending to trusted device //////////////////////	
				String SKthashed = getSha256(SKt);
				String msg = XORDecodeString(input, SKthashed);
				
				File file = new File("store.txt");
				BufferedReader br = new BufferedReader(new FileReader(file));
				String storetemp = br.readLine();
				String[] storeRead = storetemp.split("-");
				int ID = Integer.parseInt(storeRead[0]);
				int s = Integer.parseInt(storeRead[1]);
				int x = Integer.parseInt(storeRead[2]);
				Double Ts = Double.parseDouble(storeRead[3]);
				int z = Integer.parseInt(storeRead[4]);
				
				String[] received = msg.split("-"); // processing the data received from
				receivedSize =  (received[0].length()+received[1].length()+received[2].length())*16;
				System.out.println("received: "+msg);
				String cipher = received[0];
				System.out.println("cipher: "+cipher);
				Double Tr = Double.parseDouble(received[1]);
				System.out.println("Tr: "+Tr);
				int Np = Integer.parseInt(received[2]);
				System.out.println("Np: "+Np);
				int Nt = Integer.parseInt(received[3]);
				System.out.println("Nt: "+Nt);
				
				double Tsr = chebyshev(Tr, z, s);
				
				int k = (int)Tsr;
				
				try {
					// Plain Encoding----------------------------------------------------------------------
					String decryptedText = XORDecodeString(cipher, ""+k);
					
					// AES Decryption
					// ---------------------------------------------------------------------
					//String decryptedText = AES.decrypt(cipher, ""+k);
					// -------------------------------------------------------------------------------------

					// DES Encryption
					// ---------------------------------------------------------------------
					// String decryptedText = DESEncryption.decrypt(cipher, ""+k);
					// -------------------------------------------------------------------------------------

					// TripleDES Encryption
					// ---------------------------------------------------------------------
					// String decryptedText = TripleDES.decrypt(cipher, ""+k);
					// -------------------------------------------------------------------------------------

					// RC4 Encryption
					// ---------------------------------------------------------------------
					// String decryptedText = RC4Encryption.decryptText(cipher, ""+k);
					// -------------------------------------------------------------------------------------

					// RC5 Encryption
					// ---------------------------------------------------------------------
					// String decryptedText = RC5.decrypt(cipher, ""+k);
					// -------------------------------------------------------------------------------------

					// RC6 Encryption
					// ---------------------------------------------------------------------
					//String decryptedText = RC6.decrypt(cipher, "" + k);
					// -------------------------------------------------------------------------------------
				
					 String[] temp = decryptedText.split("XXPPXX");
					// String Vp = temp[0];
					System.out.println("temp[0]: " + temp[0]);
					System.out.println("decryptedText: " + decryptedText);
					int Nonce = Integer.parseInt(temp[1]);
					System.out.println("temp[1]: " + temp[1] +" and Nonce = "+ Nonce);
					
					String zstr = XOREncode("" + Ts, "" + z);
					String sha3 = getSha256(zstr);
					
					if (!sha3.equals(temp[0])) {
						System.out.println("len: "+sha3.length() +"=="+temp[0].length()+"\nPacket dropped.......");
						break;
					}
					
					String shaNd = getSha256("" + Nonce);
					String shaNt = getSha256(""+ Nt);
					String NpP =  XOREncode(sha3, ""+Np);
					String msgOUT = shaNt+"-"+shaNd+"-"+NpP;
					String messageOUT = XOREncode(msgOUT, SKthashed);
					long T3 = System.currentTimeMillis();
					String sendMessageDev = messageOUT+ T3;
					sendSize = sendMessageDev.length()*16;
					dout.writeUTF(messageOUT+"-"+T3); // send to trusted device
					dout.flush();
					//System.out.println("Send from GW: "+shaNd);
					String sessionKey_GWDn = getSha256("" + Nonce + k);
					System.out.println("sessionKey_GWDn: " + sessionKey_GWDn + "\n");
				}catch (Exception e) {
					e.printStackTrace();
				}

			}
			
		}
		
		/*

		final int PORT = 4080;
		ServerSocket serverSocket = new ServerSocket(PORT);
		Socket clientSocket = serverSocket.accept();
		DataInputStream din = new DataInputStream(clientSocket.getInputStream());
		DataOutputStream dout = new DataOutputStream(clientSocket.getOutputStream());
		// BufferedReader br=new BufferedReader(new InputStreamReader(System.in));

		// System.out.println("Server started...");
		// System.out.println("Wating for devices...");

		long startTime = 0, estimatedTime = 0, time = 0;
		long startTime_1 = System.currentTimeMillis(); // start time

		String input = "", str2 = "";
		while (!input.equals("stop")) {

			input = din.readUTF();

			startTime = System.currentTimeMillis(); // start time

			if (input.equalsIgnoreCase("stop")) {
				serverSocket.close();
				System.out.println("---->>> connection aborted.......");
				break;
			}

			File file = new File("store.txt");
			BufferedReader br = new BufferedReader(new FileReader(file));
			String storetemp = br.readLine();
			String[] storeRead = storetemp.split("-");
			int ID = Integer.parseInt(storeRead[0]);
			int s = Integer.parseInt(storeRead[1]);
			int x = Integer.parseInt(storeRead[2]);
			Double Ts = Double.parseDouble(storeRead[3]);
			int z = Integer.parseInt(storeRead[4]);

			String[] received = input.split("-"); // processing the data received from
			String cipher = received[0];
			Double Tr = Double.parseDouble(received[1]);
			double Tsr = chebyshev(Tr, z, s);
			int k = (int) Tsr;
			// System.out.println("Tsr: " + Tsr +" k: "+k );

			SecretKey secKey;

			try {
				// AES Decryption
				// ---------------------------------------------------------------------
				// String decryptedText = AES.decrypt(cipher, ""+k);
				// -------------------------------------------------------------------------------------

				// DES Encryption
				// ---------------------------------------------------------------------
				// String decryptedText = DESEncryption.decrypt(cipher, ""+k);
				// -------------------------------------------------------------------------------------

				// TripleDES Encryption
				// ---------------------------------------------------------------------
				// String decryptedText = TripleDES.decrypt(cipher, ""+k);
				// -------------------------------------------------------------------------------------

				// RC4 Encryption
				// ---------------------------------------------------------------------
				// String decryptedText = RC4Encryption.decryptText(cipher, ""+k);
				// -------------------------------------------------------------------------------------

				// RC5 Encryption
				// ---------------------------------------------------------------------
				// String decryptedText = RC5.decrypt(cipher, ""+k);
				// -------------------------------------------------------------------------------------

				// RC6 Encryption
				// ---------------------------------------------------------------------
				String decryptedText = RC6.decrypt(cipher, "" + k);
				// -------------------------------------------------------------------------------------

				String[] temp = decryptedText.split("-");
				// String Vp = temp[0];
				System.out.println("decryptedText: " + decryptedText);
				int Nonce = Integer.parseInt(temp[1]);

				String zstr = XOREncode("" + Ts, "" + z);
				String sha3 = getSha256(zstr);
				// System.out.println("-->> received Vp: " + temp[0] );
				// System.out.println("-->> Vp: " + sha3 );
				// System.out.println("-->> Nonce: " + Nonce );

				if (!sha3.equals(temp[0])) {
					// System.out.println("len: "+sha3.length() +"=="+temp[0].length()+"\nPacket
					// dropptd.......");
					break;
				}

				String sha4 = getSha256("" + Nonce);

				estimatedTime = System.currentTimeMillis() - startTime;
				time = time + estimatedTime;

				// System.out.println("estimatedTime (without comm. delay part1): " +
				// estimatedTime);

				dout.writeUTF(sha4); // send to device
				dout.flush();

				long startTimex = System.currentTimeMillis(); // start time

				// System.out.println("packet sent: " +sha4);
				String sessionKey = getSha256("" + Nonce + k);
				System.out.println("-->> Session Key: " + sessionKey + "\n");

				long estimatedTimex = System.currentTimeMillis() - startTimex;
				time = time + estimatedTimex;
				long estimatedTime_1 = System.currentTimeMillis() - startTime_1;
				System.out.println("estimatedTime (with comm. delay): " + estimatedTime_1);
				System.out.println("estimatedTime (without comm. delay): " + time);

			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		*/
	}

}
