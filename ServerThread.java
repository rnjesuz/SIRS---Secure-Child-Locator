import java.io.*;
import java.net.*;
import java.util.*;

public class ServerThread extends Thread{

	private Socket socket;
	private BufferedReader input;
	private DataOutputStream output;

	private HashMap<String, String> userHashMap = new HashMap<String, String>();
	private HashMap<String, String> beaconHashMap = new HashMap<String, String>();
	private final String USR_HM_PATH = "/database/userHashMap.dat";
	private final String BCN_HM_PATH = "/database/beaconHashMap.dat";

	private final String delim = "_";
	
	private String clientID;

	public ServerThread(Socket s) {
		socket = s;
	}

	@Override
	public void run() {
		try{
			prepareCommunication();

			String msg_rcv = input.readLine();
			String msg_sent = "NO";
			String[] msg = msg_rcv.split(delim);

			switch(msg[0]){

			case "APP":
				if(msg.length == 4){
					if(appInitialConnection(msg)) {
						System.out.println("Connection with App established!");
						appListen();
					}
				} else {
					output.writeBytes(msg_sent + '\n');
					System.out.println("Access Denied!");
					System.out.println("Sent: " + msg_sent);
				}
				break;

			case "BEACON":
				if(msg.length == 4){
					if(beaconInitialConnection(msg)) {
						System.out.println("Connection with Beacon established!");
						beaconListen();
					}
				} else {
					output.writeBytes(msg_sent + '\n');
					System.out.println("Access Denied!");
					System.out.println("Sent: " + msg_sent);
				}
				break;

			default:
				output.writeBytes(msg_sent + '\n');
				System.out.println("Sent: " + msg_sent);
				break;
			}
		} catch (IOException e) {
			System.out.println("Connection to Client Failed.");
			e.printStackTrace();
			return;
		}		
	}

	//Loads hashmaps if they exists, sets up input and output channels with server
	private void prepareCommunication() throws IOException{
		final String dir = System.getProperty("user.dir");
		System.out.println("Loading hashmaps...");

		File file = new File(dir + USR_HM_PATH);
		if(file.exists()) {
			userHashMap = (HashMap) loadStatus(USR_HM_PATH);
			System.out.println("User hashmap loaded!");
		} 

		file = new File(dir + BCN_HM_PATH);
		if(file.exists()) {
			beaconHashMap = (HashMap) loadStatus(BCN_HM_PATH);
			System.out.println("Beacon hashmap loaded!");
		}
		System.out.println("Loading done!");

		System.out.println("Creating Communication Channels...");
		input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		output = new DataOutputStream(socket.getOutputStream());
		System.out.println("Channels Created!");
	}

	//Verify if sign up or login operation
	//return true if connection established
	//return false if connection denied
	private boolean appInitialConnection(String[] msg) {
		try{
			String msg_sent = "NO";
			boolean result = false;

			switch(msg[1]){
			case "LOGIN":
				//Check if user signed up previously else not registered
				if(userHashMap.containsKey(msg[2])) {
					//Check if password matches else wrong password
					if(userHashMap.get(msg[2]).equals(msg[3])) {
						System.out.println("Logged In");
						clientID = msg[2];
						msg_sent = "OK";
						result = true;
					} else {
						System.out.println("Wrong Password");
						msg_sent = "WRONG PASS";
					}
				} else  {
					System.out.println("User not registered");
					msg_sent = "NOT REGISTERED";
				}
				break;

			case "SIGNUP":
				//Check if user is not registered else send Account already exists
				if(!userHashMap.containsKey(msg[2])) {
					userHashMap.put(msg[2], msg[3]);
					saveStatus(userHashMap, USR_HM_PATH);
					System.out.println("New account created");
					clientID = msg[2];
					msg_sent = "OK";
					result = true;
				} else  {
					System.out.println("User already registered");
					msg_sent = "ACCOUNT EXISTS";
				}
				break;

			default:
				output.writeBytes(msg_sent + '\n');
				System.out.println("Sent: " + msg_sent);
				break;
			}
			
			output.writeBytes(msg_sent + '\n');
			return result;
			
		} catch(IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	//Verify if beacon is signing up or logging in
	//returns true if connection established
	//returns false if access denied or problem with connection
	private boolean beaconInitialConnection(String[] msg) {
		try{
			String msg_sent = "NO";
			boolean result = false;

			switch(msg[1]){		

			case "SIGNUP":
				//Check if Beacon is not registered else check if password matches up
				//if Password matches, allow access, else deny it
				if(!beaconHashMap.containsKey(msg[2])) {
					beaconHashMap.put(msg[2], msg[3]);
					saveStatus(beaconHashMap, BCN_HM_PATH);
					System.out.println("New account created");
					clientID = msg[2];
					msg_sent = "OK";
					result = true;
				} else  {
					System.out.println("Beacon already registered, checking password...");
					if(beaconHashMap.get(msg[2]).equals(msg[3])) {
						System.out.println("Beacon logged in!");
						clientID = msg[2];
						msg_sent = "OK";
						result = true;
					} else System.out.println("Wrong Password!");
				}
				break;

			default:
				output.writeBytes(msg_sent + '\n');
				System.out.println("Sent: " + msg_sent);
				break;
			}
			
			output.writeBytes(msg_sent + '\n');
			return result;
			
		} catch(IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	//TODO
	//Listens to beacon after Initial Connection
	private void beaconListen() {

		try {

			System.out.println("Listening to Beacon...");

			while(true) {
				String msg_rcv = input.readLine();
				String[] msg = msg_rcv.split(delim);

				switch(msg[0]) {
				
				case "COORDS":
					System.out.println("beacon sent " + msg[1] + " coordinates");
					output.writeBytes("RECEIVED\n");
					
					//create directory to store coords
					File directory = new File("Coordinates");
					if(! directory.exists())
						directory.mkdir();
					
					//new file if one doesn't already exist
					File newFile = new File("Coordinates" + File.separator + clientID + ".txt");
					newFile.createNewFile();
					//write to file
					FileWriter fw = new FileWriter(newFile.getAbsoluteFile());
					BufferedWriter bw = new BufferedWriter(fw);
					bw.write(msg[1]);
					bw.close();
					
				default:
					break;
				}
			}	
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	//TODO
	//Listens to app after initial connection
	private void appListen() {
		try {

			System.out.println("Listening to App...");

			while(true) {
				String msg_rcv = input.readLine();
				String[] msg = msg_rcv.split(delim);

				switch(msg[0]) {
				default:
					break;
				}
			}	
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/*FUNCTIONS TO HANDLE STORE AND LOAD HASHMAPS*/
	private Object loadStatus(String name){
		Object result = null;
		try {
			final String dir = System.getProperty("user.dir");
			FileInputStream saveFile = new FileInputStream(dir + name);
			ObjectInputStream in = new ObjectInputStream(saveFile);
			result = in.readObject();
			in.close();
			saveFile.close();
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
		return result;
	}

	private void saveStatus(Serializable object, String name){
		try {
			final String dir = System.getProperty("user.dir");
			FileOutputStream saveFile = new FileOutputStream(dir + name);
			ObjectOutputStream out = new ObjectOutputStream(saveFile);
			out.writeObject(object);
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
