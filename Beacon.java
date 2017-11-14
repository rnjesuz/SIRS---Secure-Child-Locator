import java.io.*;
import java.net.Socket;

// main class
// it's purpose is to create an instance of Beacon
public class Beacon {

	public static void main(String[] args) {
		
		new BeaconClass().runBeacon();
		
	}
	
}

class BeaconClass {
	
	private String ip = "localhost";
	private int port = 6667;
	private String username;
	private String password;
	
	private Socket beaconSocket;
	private BufferedReader socketIn;
	private DataOutputStream socketOut;
	
	
	//Constructors
	public BeaconClass() {
		try {
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			System.out.println("Username?");
			username = in.readLine();
			System.out.println("Password?");
			password = in.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	public BeaconClass(String ip, int port, String username, String password){
		setIP(ip);
		setPort(port);
		setUsername(username);
		setPassword(password);
	}

	//setters
	private void setIP(String ip){
		this.ip=ip;
	}
	
	private void setPort(int port){
		this.port=port;
	}
	
	private void setUsername(String username){
		this.username=username;
	}
	
	private void setPassword(String password){
		this.password=password;
	}
	
	//getters
	private String getIp(){
		return ip;
	}
	
	private int getPort(){
		return port;
	}
	
	private String getUsername(){
		return username;
	}
	
	private String getPassword(){
		return password;
	}
	
	//Startup functions
	public void runBeacon(){
		System.out.println("Setting up beacon...");
		ConnectToServer();
		
		SignUp();
		try{
		String received = socketIn.readLine();
		System.out.println(received);
		if(received.equals("OK"))
			ImAliveCicle();
		} catch(IOException e){
			e.printStackTrace();
		}
	}
	
	private void ConnectToServer(){
		try {
			String ipToConnect=getIp();
			int portToConnect=getPort(); 
			System.out.println("Connecting to " + ipToConnect + " at port " + portToConnect);
		
			beaconSocket = new Socket(ipToConnect, portToConnect);
			socketOut = new DataOutputStream(beaconSocket.getOutputStream());
			socketIn = new BufferedReader(new InputStreamReader(beaconSocket.getInputStream()));
			System.out.println("Connection established");
		} catch (IOException e){
			e.printStackTrace();
		}
	}

	private void SignUp() {
		System.out.println("Signing Up");
		try {
			/*socketOut.writeBytes("SignUp"+ '\n');
			socketOut.writeBytes(getUsername());
			socketOut.writeBytes(getPassword());*/
			socketOut.writeBytes("BEACON_SIGNUP_" + getUsername() + "_" + getPassword() + '\n');
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
			
	private void ImAliveCicle(){
		while(true){
			System.out.println("Sending coords...");
			try {
				//TODO change to a proper coordinates system
				socketOut.writeBytes("COORDS_" + 23 + '\n');
				
				String received = socketIn.readLine();
				System.out.println(received);
				//sleep for 10 seconds
				Thread.sleep(10000);
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InterruptedException e){
				e.printStackTrace();
			}	
			
		}
	}
	
}