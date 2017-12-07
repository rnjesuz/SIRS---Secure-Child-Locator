import java.io.*;
import java.net.Socket;
import java.util.ArrayList;

public class App {

	protected static BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
	protected static Client c = new Client();
	
	public static void main(String[] args) {

		System.out.println("Welcome to Child Locator!");

		while(true){
			System.out.println("Select the option number:");
			System.out.println("(1) Sign Up");
			System.out.println("(2) Log In");
			
			String command = "";
			try {
				command=in.readLine();
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			switch(command) {
			case "1":
				try {
					c.connectToServer();
					System.out.println("Email:");
					String email = in.readLine();
					System.out.println("Password:");
					String password = in.readLine();
					System.out.println("Confirm Password:");
					String conf_password = in.readLine();
					
					if(password.equals(conf_password)) {
						String attempt = c.signUp(email, password);
						if(attempt.equals("OK"))
							authorizedCycle();
						continue;
					}
					else continue;
				} catch (IOException e) {
					e.printStackTrace();
				}
				break;
				
			case "2":
				try {
					c.connectToServer();
					System.out.println("Email:");
					String email = in.readLine();
					System.out.println("Password:");
					String password = in.readLine();

					String attempt = c.login(email, password);
					if(attempt.equals("OK"))
						authorizedCycle();
			
					continue;	
				} catch (IOException e) {
					e.printStackTrace();
				}
				break;
			
			case "":
				break;
			default:
				break;
			}
		}
	}
	
	private static void authorizedCycle(){
		
		while(true){
			
			System.out.println("Select the option number:");
			System.out.println("(1) Add Beacon");
			System.out.println("(2) List Beacons");
			System.out.println("(3) Request Coords");
			
			String command = "";
			try {
				command=in.readLine();
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			switch(command) {
			case "1":
				//ADD_BEACONID_BEACONPASS
				try {
					System.out.println("Beacon ID:");
					String BeaconID = in.readLine();
					System.out.println("Beacon Password:");
					String BeaconPassword = in.readLine();
					
					c.addBeacon(BeaconID, BeaconPassword);
					continue;
				} catch (IOException e) {
					e.printStackTrace();
				}
				break;
				
			case "2":
				//LIST
				c.getList();
				break;
			
			case "3":
				try {
					//REQ_BEACONID
					System.out.println("Beacon ID:");
					String BeaconID = in.readLine();
					System.out.println("Beacon Password:");
					String BeaconPassword = in.readLine();
					c.getCoordinates(BeaconID, BeaconPassword);
					continue;
				} catch (IOException e) {
					e.printStackTrace();
				}
				break;
				
			case "":
				break;
				
			default:
				break;
			}
		}
		
	}
	
}
