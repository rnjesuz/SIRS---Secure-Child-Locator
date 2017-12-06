import java.io.*;
import java.net.Socket;

public class App {


	public static void main(String[] args) {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		Client c = new Client();
		
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
					c.signUp(email, password);
					continue;
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
					System.out.println("Confirm Password:");
					String conf_password = in.readLine();
					
					if(password.equals(conf_password)) {
						c.login(email, password);
					}
					else break;
					
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