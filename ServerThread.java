import java.io.*;
import java.net.*;
import java.util.*;

import javax.crypto.*;

import java.nio.file.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class ServerThread extends Thread{

	private Socket socket;
	private DataInputStream input;
	private DataOutputStream output;
	
	private PublicKey cli_pubkey;
	private PublicKey server_pubkey;
	private PrivateKey server_privkey;
	private Cipher cipher;

	//map of every appID and its key
	private HashMap<String, String> userHashMap = new HashMap<String, String>();
	//map of every beaconID and its key
	private HashMap<String, String> beaconHashMap = new HashMap<String, String>();
	//map of every appID and the beacons they have access to
	private HashMap<String, ArrayList<String>> appBeacons = new HashMap<String, ArrayList<String>>();

	private final String USR_HM_PATH = "/database/userHashMap.dat";
	private final String BCN_HM_PATH = "/database/beaconHashMap.dat";
	private final String APP_BCN_PATH = "/database/appBeacons.dat";

	private final String delim = "_";

	//ID of the connected client (either app or beacon)
	private String clientID;

	public ServerThread(Socket s, PublicKey pub, PrivateKey priv) {
		socket = s;
		server_pubkey = pub;
		server_privkey = priv;
	}

	@Override
	public void run() {
		try{

			prepareCommunication();
			loadHashMaps();	
				
			String msg_rcv = rcvMsg();
			String msg_sent = "NO";
			String[] msg = msg_rcv.split(delim);

			switch(msg[0]){

			case "APP":
				if(msg.length == 4){
					if(appInitialConnection(msg)) {
						System.out.println("Connection with App established!");
						printHashMaps();
						appListen();
					}
				} else {
					sendMsg(msg_sent);
					System.out.println("Access Denied!");
				}
				break;

			case "BEACON":
				if(msg.length == 4){
					if(beaconInitialConnection(msg)) {
						System.out.println("Connection with Beacon established!");
						//TODO REMOVE
						printHashMaps();
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
		System.out.println("Creating Communication Channels...");
		input = new DataInputStream(new BufferedInputStream (socket.getInputStream()));
		output = new DataOutputStream( new BufferedOutputStream (socket.getOutputStream()));
		System.out.println("Channels Created!");
		
		//###DRAFT_BEGIN###
			//receive client public key
			try {
				System.out.println("Waiting for client public key");
				byte[] msg = new byte [input.readInt()];
				input.readFully(msg);
				System.out.println("Client Public Key: " + new String(msg, "UTF-8"));
				cli_pubkey =  KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(msg));
			} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
				System.out.println("Client Public Key not Received");
			}
		
			//send public key to client
			byte[] aux = server_pubkey.getEncoded();
			System.out.println("Sending Server Public Key: " + aux);
			output.writeInt(aux.length);
			output.write(aux);
			output.flush();
			System.out.println("Sent Server Public Key");
		//###DRAFT_END###
		
		//TODO: fix this
		try {
			Cipher cipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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
				loadHashMaps();
				//Check if user signed up previously else not registered
				if(userHashMap.containsKey(msg[2])) {
					//Check if password matches else wrong password
					if(userHashMap.get(msg[2]).equals(msg[3])) {
						System.out.println("Log In: SUCCESS");
						clientID = msg[2];
						msg_sent = "OK";
						result = true;
					} else {
						System.out.println("Log In: FAIL->Wrong Password");
						msg_sent = "WRONG PASS";
					}
				} else  {
					System.out.println("Log in: FAIL->User not registered");
					msg_sent = "NOT REGISTERED";
				}
				sendMsg(msg_sent);
				break;

			case "SIGNUP":
				//Check if user is not registered else send Account already exists
				loadHashMaps();
				if(!userHashMap.containsKey(msg[2])) {
					userHashMap.put(msg[2], msg[3]);
					saveStatus(userHashMap, USR_HM_PATH);
					System.out.println("New account created");
					clientID = msg[2];
					msg_sent = "OK";
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
				loadHashMaps();
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

			while(true) {
				
				System.out.println("Listening to App...");
				
				String msg_rcv = input.readLine();
				String[] msg = msg_rcv.split(delim);
				String msg_sent = "NO";
				System.out.println(msg_rcv);
				
				switch(msg[0]) {
				
				case "LIST" :
					System.out.println("Sending beacons that user owns...");
					loadHashMaps();
					printHashMaps();
					
					if(appBeacons.containsKey(clientID)) {
						ArrayList<String> list = appBeacons.get(clientID);
						msg_sent = "";
						for(String beacon : list) {
							System.out.println(beacon);
							msg_sent += beacon + delim;
						}
						System.out.println("List sent!");
					} else {
						System.out.println("No elements in list...");
					}
					
					System.out.println(msg_sent);
					output.writeBytes(msg_sent + '\n');
					break;
				
				//case to add a new beacon				
				case "ADD":
					//ADD_BEACONID_BEACONPASS
					System.out.println("App trying to add beacon: " + msg[1]);

					loadHashMaps();
					//checks for existence of beacon
					if(beaconHashMap.containsKey(msg[1])) {
						//checks if password matches
						if(beaconHashMap.get(msg[1]).equals(msg[2])){
							//check if  client exist in map
							//if not, adds it associated to a List containing the beaconID
							if(! appBeacons.containsKey(clientID)){
								ArrayList<String> newList =  new ArrayList<String>();
								newList.add(msg[1]);
								appBeacons.put( clientID, newList );
								saveStatus(appBeacons, APP_BCN_PATH);
								msg_sent = "OK";
								System.out.println("Beacon added to client");
							}
							else{
								//client has a map. Check if beacon is already added

								//get list of beacons
								ArrayList<String> beacons = appBeacons.get(clientID);
								//is beacon added?
								if(beacons.contains(msg[1]))
									msg_sent = "ALREADY ADDED";
								else{
									//no...so, we add
									beacons.add(msg[1]);
									appBeacons.put(clientID, beacons);
									saveStatus(appBeacons, APP_BCN_PATH);
									msg_sent = "OK";
									System.out.println("Beacon added to client");
								}
							}				
						}
					} else {
						System.out.println("Beacon doesn't exist");
					}

					//TODO REMOVE
					printHashMaps();
					
					output.writeBytes(msg_sent + '\n');
					break;

					//case to request coords from a beacon
				case "REQ":
					//REQ_BEACONID
					System.out.println("App tried to request coords from beacon: " + msg[1]);
					loadHashMaps();
					//check if beacon was added
					ArrayList<String> beacons = appBeacons.get(clientID);
					if(beacons.contains(msg[1])){
						//beacon was added
						//read from file 
						byte[] encoded = Files.readAllBytes(Paths.get("Coordinates" + File.separator + msg[1]));
						msg_sent = new String(encoded);
					}
					output.writeBytes(msg_sent + '\n');
					break;

				default:
					System.out.println("Operation Denied");
					output.writeBytes(msg_sent + '\n');
					break;
				}
			}	
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	//#################################CIPHER OPERATIONS#############################################
    private void sendMsg(String msg) {
        //TODO: Add counter, signature, SALT(?), etc...
        try {
            byte[] send_msg = encrypt(msg);
            output.writeInt(send_msg.length);
            output.write(send_msg);
            System.out.println("Send Message: SUCCESS");
        } catch (IOException e) {
            System.out.println("Send Message: FAIL");
        }
    }

    private String rcvMsg() {
        String msg = "";
        //TODO: confirm counter, signature and isolate the message
        try {
            byte[] rcvd_msg = new byte[input.readInt()];
            input.readFully(rcvd_msg);
            msg = decrypt(rcvd_msg);
            System.out.println("Receive Message: SUCCESS");
        } catch (IOException e) {
            System.out.println("Receive Message: FAIL");
        }
        return msg;
    }

    private byte[] encrypt(String msg) {
        byte[] result = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, server_pubkey);
            result = cipher.doFinal(msg.getBytes("UTF-8"));
            System.out.println("Encrypted message: " + new String(result, "UTF-8"));
        } catch (InvalidKeyException | UnsupportedEncodingException | IllegalBlockSizeException
                | BadPaddingException e) {
            System.out.println("Encryption: FAILED");
        }
        return result;
    }

    private String decrypt(byte[] msg) {
        String result = "";
        try {
            cipher.init(Cipher.DECRYPT_MODE, server_privkey);
            byte[] aux = cipher.doFinal(msg);
            result = new String(aux, "UTF-8");
            System.out.println("Decrypted message: " + result);
        } catch (InvalidKeyException | UnsupportedEncodingException | IllegalBlockSizeException
                | BadPaddingException e) {
            System.out.println("Decryption: FAILED");
        }
        return result;
    }
	
	//#################################HASH-MAPS#####################################################
	private void loadHashMaps() {
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

		file = new File(dir + APP_BCN_PATH);
		if(file.exists()) {
			appBeacons = (HashMap) loadStatus(APP_BCN_PATH);
			System.out.println("App's beacons hashmap loaded!");
		}

		System.out.println("Loading done!");
	}

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
	
	private void printHashMaps () {
		System.out.println("######BEACON'S HASHMAP######");  
		for (String name: beaconHashMap.keySet()){
			String key =name.toString();
			System.out.println(key);  
		}
		System.out.println("######USER'S HASHMAP######");  
		for (String name: userHashMap.keySet()){
			String key =name.toString();
			System.out.println(key);  
		}
		System.out.println("######APP-BEACON ASSOCIATION HASHMAP######");  
		for (String name: appBeacons.keySet()){
			String key =name.toString();
			for(String value : appBeacons.get(name)) {
				System.out.println(key + " " + value.toString());  
			}
		}
		System.out.println("######END######");  
	}
}
