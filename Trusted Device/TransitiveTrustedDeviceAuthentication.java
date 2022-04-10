import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.math.BigInteger;
import java.net.ServerSocket;
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

public class TransitiveTrustedDeviceAuthentication {

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
		
		
		double Eelec = 50.0;
		double Eamp = 0.1;
		double d = 1.0;
		long size1 = -1, size2 = -1, size3 = -1, size4 = -1;
		
		final String HOST = "127.0.0.1";
		final int PORTin = 4085;
		final int PORTout = 4086;
		String SKt = "xs24h1wXGV/QgzARB1fPAgmv4s3yEPcIDwhnCxqxuIy9a0ATYE/g5+vVxCTZqnK0/R0JLGjR/+x0D91+i+72Uw";
		int DIDt = 33333;
		
/////////////////////// sockets for the new device ///////////////////////////////////////////////////////////////
		ServerSocket trustedServerSocket = new ServerSocket(PORTin);
		Socket trustedClientSocket = trustedServerSocket.accept();
		DataInputStream Device_indata=new DataInputStream(trustedClientSocket.getInputStream());  
		DataOutputStream Device_outdata=new DataOutputStream(trustedClientSocket.getOutputStream());  

/////////////////////// sockets for the new device ///////////////////////////////////////////////////////////////		
		
		Socket GWsocket = new Socket(HOST, PORTout);
		DataInputStream GWindata=new DataInputStream(GWsocket.getInputStream());  
		DataOutputStream GWoutdata=new DataOutputStream(GWsocket.getOutputStream()); 
		
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////		
		
		/*             PING TESTING
		 * System.out.println("Ping received from: "+Device_indata.readUTF());
		 * 
		 * System.out.println("Ping sent to Gateway");
		 * GWoutdata.writeUTF("Trusted Device"); GWoutdata.flush();
		 * 
		 * System.out.println("Ping received from: "+GWindata.readUTF());
		 * 
		 * System.out.println("Ping sent to New Device");
		 * Device_outdata.writeUTF("Trusted Device"); Device_outdata.flush();
		 */
		
		String input = "", input2 = "";
		while (!input.equals("stop")) {
			
			//////////////// receives from new device //////////////////////
			input = Device_indata.readUTF();
			//System.out.println("Received at Dt from Dn: "+ input);
			
			if (input.equalsIgnoreCase("stop")) {
				GWoutdata.writeUTF(input);
				GWoutdata.flush();
				break;
				
			}else {
				
				////////////////Sending to Gateway //////////////////////
				Random rnd = new SecureRandom();
				int Nt = BigInteger.probablePrime(15, rnd).intValue();
				int Np = BigInteger.probablePrime(15, rnd).intValue();
				String userReceived[] = input.split("-");
				String message = userReceived[0] +"-"+userReceived[1]+ "-" + Np + "-" +Nt;
				String receiveMagUser = userReceived[0]+userReceived[1]+userReceived[2]+userReceived[3];
				size1 = receiveMagUser.length()*16; //SIZE of received data from user
				String SKthashed = getSha256(SKt);
				String msg = XOREncode(message, SKthashed);
				long T2 = System.currentTimeMillis();
				String AIDt = XOREncode(getSha256(""+T2), ""+DIDt);
				String sizeSendGateway = msg+AIDt+DIDt;
				size2 = sizeSendGateway.length()*16; //SIZE of send data from GW
				GWoutdata.writeUTF(msg+"-"+AIDt+"-"+DIDt);
				GWoutdata.flush();
				//System.out.println("Send from Dn: "+msg);
				
				////////////////receives from Gateway //////////////////////
				input2 = GWindata.readUTF();
				String msg_GW = XORDecodeString(input2, SKthashed);
				String[] received = msg_GW.split("-"); //shaNt+"-"+shaNd+"-"+NpP;
				String shaNtP = getSha256(""+Nt);
				size3 = (received[0].length()+received[1].length())*16; //size of received data from GW
				if(!shaNtP.equals(received[0])) {
					System.out.println("!!! Error !!!!");
					break;
				}	
				
				////////////////Sending to New Device //////////////////////
				//System.out.println("Np+received[1]: "+ Np+received[1]);
				//System.out.println("Np: "+Np);
				String sessionKey_DtDn = getSha256(""+Np+ received[1]);
				
				String messageOUTDn = received[1]+"-"+received[2];
				System.out.println("sessionKey_DtDn: " + sessionKey_DtDn +"\n");
				long T4 = System.currentTimeMillis();
				String sendMesasgeUser = received[0]+received[1]+T4;
				size4 = sendMesasgeUser.length()*16;
				Device_outdata.writeUTF(messageOUTDn+"-"+T4);
				Device_outdata.flush();
				
				long receiveMsgSize = size1+size3;
				long sendMsgSize = size2+size4;
				long afterUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
				double sendEnergy = (Eelec*sendMsgSize)+(Eamp*sendMsgSize*d*d);
				double receiveEnergy = Eelec*receiveMsgSize;
				double totalEnergy = sendEnergy+receiveEnergy;
				
				System.out.println("memory usage: " + afterUsedMem/(1024*1024) + " MB");
				System.out.println("Communication cost (send message size): " + sendMsgSize + " bytes");
				System.out.println("receive message size: " + receiveMsgSize + " bytes");
				System.out.println("Sending Energy: " + sendEnergy + " nJ");
				System.out.println("Receiving Energy: " + receiveEnergy + " nJ");
				System.out.println("Total Energy: " + totalEnergy + " nJ");
				
				String store = afterUsedMem/(1024*1024)+"\t"+sendMsgSize+"\t"+receiveMsgSize+"\t"+sendEnergy+"\t"+receiveEnergy+"\t"+totalEnergy;
				Writer output;
				output = new BufferedWriter(new FileWriter("Results.txt", true));  //clears file every time
				output.append(store+"\n");
				output.close();
			}
		}

	}

}
