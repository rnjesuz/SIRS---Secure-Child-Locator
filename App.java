import java.io.*;
import java.net.Socket;

public class App {


	public static void main(String[] args) {
		final String server_ip = "localhost";
		final int server_port = 6667;
		BufferedReader input;
		DataOutputStream output;

		String option;
		final String delim = "_";

		Socket clientSocket;
		try {
			System.out.println("Connecting to " + server_ip + " at port " + server_port);

			clientSocket = new Socket(server_ip, server_port);
			output = new DataOutputStream(clientSocket.getOutputStream());
			input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

			System.out.println("Connection established");
			System.out.println("Select option number:");
			System.out.println("(1) Login");
			System.out.println("(2) Sign Up");			

			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			option = br.readLine();

			String email;
			String pass;
			String conf;
			
			String beaconID;
			String beaconPass;
			
			String msg;

			switch(option){
			//LOGIN
			case "1":
				while(true) {
					System.out.println("Email:");
					email = br.readLine();
					System.out.println("Password:");
					pass = br.readLine();
					output.writeBytes("APP" + delim + "LOGIN" + delim + email + delim + pass + "\n");
					System.out.println("Sending Message: " + "APP" + delim + "LOGIN" + delim + email + delim + pass);
					
					msg = input.readLine();
					if(msg.equals("OK")) {
						System.out.println("Logged in!");
						System.out.println("Chose Option number: ");
						System.out.println("(1)Add Beacon");
						System.out.println("(2)Request Coordinates from Beacon");
						option = br.readLine();
						
						switch(option) {
						case "1":
							System.out.println("Beacon ID:");
							beaconID = br.readLine();
							System.out.println("Beacon Password:");
							beaconPass = br.readLine();
							output.writeBytes("ADD" + delim + beaconID + delim + beaconPass + '\n');
							
							msg = input.readLine();
							
							if(msg.equals("OK")) {
								System.out.println("Beacon successfuly added!");
								break;
							}
							
							if(msg.equals("ALREADY ADDED")) {
								System.out.println("Beacon already added to list...");
								break;
							}
							
							if(msg.equals("DOESNT EXIST")) {
								System.out.println("Beacon doesn't exist...");
								break;
							}
							
							if(msg.equals("NO")) {
								System.out.println("Access Denied.");
								break;
							}
							
							break;
						case "2":
							break;
						default:
							break;
						}
						
						break;
					}
					
					if(msg.equals("WRONG PASS")) {
						System.out.println("Wrong Password, try again...");
					}
					
					if(msg.equals("NOT REGISTERED")) {
						System.out.println("Account doesn't exist, please sign up...");
						break;
					}
					
					if(msg.equals("NO")) {
						System.out.println("Access Denied.");
						break;
					}
				}
				break;

			//SIGN UP	
			case "2":
				while(true) {
					System.out.println("Email:");
					email = br.readLine();
					System.out.println("Password:");
					pass = br.readLine();
					System.out.println("Confirm Password:");
					conf = br.readLine();
					
					if(pass.equals(conf)) {
						output.writeBytes("APP" + delim + "SIGNUP" + delim + email + delim + pass + "\n");
						
						msg = input.readLine();
						if(msg.equals("OK")) {
							System.out.println("Account Registered! Try to Login!");
							break;
						}						
						if(msg.equals("ACCOUNT EXISTS")) {
							System.out.println("Account already exists, Try again...");
							break;
						}	
						if(msg.equals("NO")) {
							System.out.println("Access Denied.");
							break;
						}	
						
					} else {
						System.out.println("Password doesn't match, Try again...");
					}
				}
				break;

			default:
				System.out.println("Command not recognized, shutting down...");
				break;
			}
			clientSocket.close();
			
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
}
