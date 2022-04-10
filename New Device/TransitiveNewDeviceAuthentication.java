import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.Writer;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Random;


public class TransitiveNewDeviceAuthentication {

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
		
		Instant responseStart = Instant.now();
		Instant responseEnd = Instant.now();
		long handshakeDuration = -1;
		long sendMsgSize = -1, receiveMsgSize = -1;;
		// memory usage before execution
		long beforeUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
		double Eelec = 50.0;
		double Eamp = 0.1;
		double d = 1.0;
		
		long count = 0, total = 0, avgElapsedTime = 0, n=1;
		final String HOST = "127.0.0.1";
		final int PORT = 4085;
		String exitStatus= "";
		Socket socket = new Socket(HOST, PORT);
		DataInputStream indata=new DataInputStream(socket.getInputStream());  
		DataOutputStream outdata=new DataOutputStream(socket.getOutputStream());  
		BufferedReader brk=new BufferedReader(new InputStreamReader(System.in));
		//AES.encrypt("abcd", ""+123);
		/*             PING TESTING
		 * System.out.println("ping sent to trusted device");
		 * outdata.writeUTF("new device"); outdata.flush();
		 * System.out.println("ping received from "+indata.readUTF());
		 */
		
		while (count<n) {
			
			
			//exitStatus=brk.readLine();//keyboard input

			if (exitStatus.equalsIgnoreCase("stop")) {
				outdata.writeUTF(exitStatus);
				outdata.flush();
				break;
			}
			
			Instant start = Instant.now();
			
			
			File file = new File("store.txt");
			BufferedReader br = new BufferedReader(new FileReader(file));
			String storetemp = br.readLine();
			String[] storeRead = storetemp.split("-");
			String Vstore = storeRead[0];
			int Xstore = Integer.parseInt(storeRead[1]);
			Double Tsstore = Double.parseDouble(storeRead[2]);
			
			Random rnd = new SecureRandom();
			int Nonce = BigInteger.probablePrime(15, rnd).intValue();
			
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
			
		//	long T1 = System.currentTimeMillis(); 
		//	int AID = 
					
			int k = (int)Trs;
			System.out.println("Tsr: " + Trs +"  K: "+k);
			String encrypt = sha3+"XXPPXX"+Nonce;
			
			try {
				// Plain Encoding----------------------------------------------------------------------
				String cipherText = XOREncode(encrypt, ""+k);
				
				
				// AES Encryption --------------------------------------------------------------------
				//String cipherText = AES.encrypt(encrypt, ""+k);
				//System.out.println("encoded: "+cipherText);
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
				// String cipherText = RC5.encrypt(encrypt, ""+k);
				//-------------------------------------------------------------------------------------

				// RC6 Encryption ---------------------------------------------------------------------				
				//String cipherText = RC6.encrypt(encrypt, ""+k);
				//-------------------------------------------------------------------------------------

				System.out.println("plaintext:"+ encrypt);
				System.out.println("cipherText:"+cipherText);
				long T1 = System.currentTimeMillis();
				String AID = XOREncode(getSha256(""+T1), ""+DID);
				String sendtoDev = cipherText+"-"+Tr+"-"+AID+"-"+T1;
				String sendsize = AID+cipherText+Tr+T1;
				sendMsgSize = sendsize.length()*16;
				////////////////Sending to trusted device //////////////////////
				outdata.writeUTF(cipherText+"-"+Tr+"-"+AID+"-"+T1);
				outdata.flush();
				System.out.println("Sent to Dt: "+cipherText+"-"+Tr);
				
				responseStart = Instant.now(); // start of response time
				
			}catch (Exception e) {
				// TODO: handle exception
				e.printStackTrace();
			}
			
			////////////////receiving from trusted device //////////////////////
			String input2 = indata.readUTF();
			
			responseEnd = Instant.now(); // End of response time
			
			String[] receivedTD = input2.split("-"); 
			//System.out.println("receivedTD[1]:"+receivedTD[1]);
			long T5 = System.currentTimeMillis();
			String receivesize = receivedTD[0]+receivedTD[1]+receivedTD[2];
			receiveMsgSize = receivesize.length()*16;
			
			String hashedNonce = getSha256(""+Nonce);
			if(!hashedNonce.equals(receivedTD[0])) {
				System.out.println("Packet Dropped...");
				break;
			}
			
			String Np = XORDecodekey(receivedTD[1], sha3).trim();
			//System.out.println("Np+receivedTD[0]: "+Np+receivedTD[0]);
			//System.out.println("strNp:"+strNp);
			//int Np = Integer.parseInt(strNp.trim());
			//System.out.println("Np+receivedTD[0]: "+Np+receivedTD[0]);
			String sessionKey_DtDn = getSha256(""+Np+receivedTD[0]);
			String sessionKey_GWDn = getSha256("" + Nonce + k);
			
			System.out.println("sessionKey_DtDn: "+sessionKey_DtDn);
			System.out.println("sessionKey_GWDn: "+sessionKey_GWDn+"\n");
			
			Instant finish = Instant.now();
			handshakeDuration = Duration.between(start, finish).toMillis();
			
			count++;
			
		}
		outdata.writeUTF("stop");
		outdata.flush();

		//memory usage after execution
		long afterUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
		long actualMemUsed=afterUsedMem-beforeUsedMem;
		
		long responseTime = Duration.between(responseStart, responseEnd).toMillis();
		double sendEnergy = (Eelec*sendMsgSize)+(Eamp*sendMsgSize*d*d);
		double receiveEnergy = Eelec*receiveMsgSize;
		double totalEnergy = sendEnergy+receiveEnergy;
		
		System.out.println("\nresponse time: "+responseTime+" milliseconds");
		System.out.println("handshake duration: "+handshakeDuration+" milliseconds");
		System.out.println("memory usage: " + afterUsedMem/(1024*1024) + " MB");
		System.out.println("Communication cost (send message size): " + sendMsgSize + " bytes");
		System.out.println("receive message size: " + receiveMsgSize + " bytes");
		System.out.println("Sending Energy: " + sendEnergy + " nJ");
		System.out.println("Receiving Energy: " + receiveEnergy + " nJ");
		System.out.println("Total Energy: " + totalEnergy + " nJ");
		
		String store = responseTime+"\t"+handshakeDuration+"\t"+afterUsedMem/(1024*1024)+"\t"+sendMsgSize+"\t"+receiveMsgSize+"\t"+sendEnergy+"\t"+receiveEnergy+"\t"+totalEnergy;
		Writer output;
		output = new BufferedWriter(new FileWriter("Results.txt", true));  //clears file every time
		output.append(store+"\n");
		output.close();       
		
	} 

}
