
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;
import java.io.*;  

class IoTDeviceRegistration{  
	
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
	
	public static void main(String args[])throws Exception{  
		
		final String HOST = "127.0.0.1";
        final int PORT = 4082;
        
        Socket socket = new Socket(HOST, PORT);
		DataInputStream din=new DataInputStream(socket.getInputStream());  
		DataOutputStream dout=new DataOutputStream(socket.getOutputStream());  
		BufferedReader br=new BufferedReader(new InputStreamReader(System.in));  

		long startTime = System.currentTimeMillis(); //start time
		long startTime1 =0, estimatedTime1 = 0, time = 0;
		
		
		String input="";  
		while(!input.equals("stop")){  
			input=br.readLine();  
			
			if (input.equalsIgnoreCase("stop")) {
				dout.writeUTF(input);
				dout.flush();
				//System.out.println("---->>> connection aborted.......");
            	break;
            }
			
			startTime1 = System.currentTimeMillis();
			
			IoTDeviceRegistration dev = new IoTDeviceRegistration();
	    	LocalDateTime date = LocalDateTime.now();
	    	dev.Rd = Math.abs(ThreadLocalRandom.current().nextInt());
	    	//System.out.println("Random Ri: " + dev.Rd); 
	    	dev.Di = 100301;
	    	dev.PW = 1234;
	    	dev.PID = (dev.Di ^ dev.Rd);
	    	dev.T = date.toLocalTime().toSecondOfDay();
	    	dev.PIN = (dev.PW ^ dev.T);
	    	//System.out.println("PID: " + (dev.PIN^dev.T));
	    	dev.com1 = dev.PID+"-"+dev.PIN+"-"+dev.Rd;
	    	String str = "\n";
	        //System.out.println("Device writing to file..."+str);
			
			String sha = getSha256(Integer.toString(dev.PIN^dev.PID));
			String sha1 = getSha256(Integer.toString(dev.Di^dev.PW));
			//System.out.println("---->>> registration phase.......");
			
			estimatedTime1 = System.currentTimeMillis() - startTime1;
			time = time+estimatedTime1;
			
           	dout.writeUTF(dev.com1);
           	dout.flush();
        	//System.out.println("reg. phase..."+dev.com1);
        	
            String[] fromGateway = din.readUTF().split("-");
            
            startTime1 = System.currentTimeMillis();
            
            String decode1 = XORDecodekey(fromGateway[0], sha); 
            double zp = Double.parseDouble(decode1);
            int z = ((int)zp^dev.PID);
            int x = Integer.parseInt(fromGateway[1]);
            double Ts = Double.parseDouble(fromGateway[2]);
            String v = XOREncode(sha1, ""+z);
            
            String store = v+"-"+x+"-"+Ts;
            //System.out.println("store: "+store);
        	Writer output;
    		output = new BufferedWriter(new FileWriter("store.txt"));  //clears file every time
    		output.append(store+"\n");
    		output.close();               
            //System.out.println("received from gateway: " + z+"--"+x+"---"+Ts);
            
            estimatedTime1 = System.currentTimeMillis() - startTime1;
			time = time+estimatedTime1;
			long estimatedTime = System.currentTimeMillis() - startTime;
			System.out.println("estimatedTime (with comm. delay): " + estimatedTime);
	        System.out.println("estimatedTime (without comm. delay): " + time);
		}  

		dout.close();  
		socket.close();
	}
	
} 