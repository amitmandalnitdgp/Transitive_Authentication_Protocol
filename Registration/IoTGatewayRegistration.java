import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.io.*;
import java.math.BigInteger;  

class IoTGatewayRegistration{  
	
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
	
	
	public static void main(String args[])throws Exception{  
        final int PORT = 4082;
        ServerSocket serverSocket = new ServerSocket(PORT);
        Socket clientSocket = serverSocket.accept();
        DataInputStream din=new DataInputStream(clientSocket.getInputStream());  
		DataOutputStream dout=new DataOutputStream(clientSocket.getOutputStream());  
		BufferedReader br=new BufferedReader(new InputStreamReader(System.in));
		
		long startTime = System.currentTimeMillis(); //start time
		long startTime1 =0, estimatedTime1 = 0, time = 0;
		
		
        //System.out.println("Gateway started...");
        //System.out.println("Wating for devices...");
        
        String input="",str2="";  
		while(!input.equals("stop")){  
			
			input=din.readUTF();  
			
			if (input.equalsIgnoreCase("stop")) {
            	serverSocket.close();
            	System.out.println("---->>> connection aborted.......");
                break;
            }
			startTime1 = System.currentTimeMillis();
			//System.out.println("---->>> registration phase.......");                            	
        	String[] com1 = input.split("-");
        	//System.out.println("from device: "+ input);
        	int PID = Integer.parseInt(com1[0]);
        	int PIN = Integer.parseInt(com1[1]);
        	int Rd = Integer.parseInt(com1[2]);
        	int ID = (PID^Rd);
        	Random rand = new Random();
        	int low = 10;
        	int high = 100;
        	int s = rand.nextInt(high-low) + low;
        	int x = rand.nextInt(high-low) + low;
        	Random rnd = new SecureRandom();
    		int z = BigInteger.probablePrime(6, rnd).intValue();
        	double Ts = chebyshev(x, z, s);
        	//System.out.println("Ts(x): " + Ts);
        	int zp = (z^PID);
        	String sha = getSha256(Integer.toString(PIN^PID));
        	String CK = XOREncode(sha, ""+zp);
        	//System.out.println("--->z: " + z+"  x---"+x);
        	String store = ID+"-"+s+"-"+x+"-"+Ts+"-"+z;
        	Writer output;
    		output = new BufferedWriter(new FileWriter("store.txt"));  //clears file every time
    		output.append(store+"\n");
    		output.close();
    		
    		estimatedTime1 = System.currentTimeMillis() - startTime1;
			time = time+estimatedTime1;
    		
    		dout.writeUTF(CK+"-"+x+"-"+Ts); // send to device
    		dout.flush();
    		
    		long estimatedTime = System.currentTimeMillis() - startTime;
    		System.out.println("estimatedTime (with comm. delay): " + estimatedTime);
	        System.out.println("estimatedTime (without comm. delay): " + time);
    		
		}
        
		din.close();  
		clientSocket.close();  
		serverSocket.close();

	}
}  