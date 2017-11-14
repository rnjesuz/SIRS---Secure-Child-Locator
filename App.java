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
