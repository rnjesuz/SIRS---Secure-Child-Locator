import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class ServerThread extends Thread{

	private Socket socket;
	private DataInputStream input;
	private DataOutputStream output;

	private PublicKey cli_pubkey;
	private PublicKey server_pubkey;
	private PrivateKey server_privkey;
	private byte[] iv = new byte[0];
	private SecretKey sk;

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
			tradeKeys();
			generateSessionKey();
			sendSessionKey();

			loadHashMaps();	

			String msg_rcv = new String(rcvMsg("AES"), "UTF-8");

			if(msg_rcv.equals(null)) {
				System.out.println("Message Error");
				return;
			}

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
					//sendMsg(msg_sent);
					System.out.println("Access Denied!");
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
		System.out.println("Creating Communication Channels...");
		input = new DataInputStream(socket.getInputStream());
		output = new DataOutputStream (socket.getOutputStream());
		System.out.println("Channels Created!");	
	}

	private void tradeKeys() {
		try {
			System.out.println("Receiving Public Key from Client");

			//Receive encoded key
			byte[] encoded_clipub = new byte[input.readInt()];
			input.readFully(encoded_clipub);

			System.out.println("Key Received: ");
			System.out.println(new String(encoded_clipub, "UTF-8"));
			System.out.println("Size: " + encoded_clipub.length);

			//convert bytes into key
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded_clipub);
			cli_pubkey = keyFactory.generatePublic(publicKeySpec);
			System.out.println("Key Converted!");
			System.out.println(new String(cli_pubkey.getEncoded(), "UTF-8"));

			//Send key
			output.writeInt(server_pubkey.getEncoded().length);
			output.write(server_pubkey.getEncoded());
			output.flush();
			System.out.println("Sent Server Public Key");

		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}


	private void generateSessionKey() {
		try {
			//generate key and IV
			KeyGenerator generator = KeyGenerator.getInstance( "AES" );
			sk = generator.generateKey();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}

	private void sendSessionKey() {		

		int ivSize = 16;
		byte[] encrypted = encrypt(sk.getEncoded(), "RSA");

		generateIV(null);

		byte[] msg = new byte[ivSize + encrypted.length];
		System.arraycopy(iv, 0, msg, 0, ivSize);
		System.arraycopy(encrypted, 0, msg, ivSize, encrypted.length);

		//NOTE: msg = iv + {sk}cli_pub

		try {
			output.writeInt(msg.length);
			output.write(msg);
			output.flush();

			System.out.println("IV: " + new String(iv, "UTF-8"));
			System.out.println("Session Key: " + new String(sk.getEncoded(), "UTF-8"));

			msg = null;
			msg = rcvMsg("AES");
			if(msg == null) {
				System.out.println("Message Error");
				return;
			}
			String response = new String(msg, "UTF-8");

			if(!response.equals("OK")) {
				System.out.println("Response was not what was expected...");
			} else System.out.println("Session Key communication Established!");

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private String hashPasswordSHA512 (String password, String salt) {
		String hashedPass = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(salt.getBytes("UTF-8"));
			byte[] bytes = md.digest(password.getBytes("UTF-8"));
			StringBuilder sb = new StringBuilder();
			for(int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			hashedPass = sb.toString();
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return hashedPass;
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
					String hashedPass = hashPasswordSHA512(msg[3], msg[2]); //hashes password using username as salt
					if(userHashMap.get(msg[2]).equals(hashedPass)) {
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
				sendMsg(msg_sent.getBytes(), "AES");
				break;

			case "SIGNUP":
				//Check if user is not registered else send Account already exists
				loadHashMaps();
				if(!userHashMap.containsKey(msg[2])) {
					String hashedPass = hashPasswordSHA512(msg[3], msg[2]); //hashes password using username as salt
					userHashMap.put(msg[2], hashedPass);
					saveStatus(userHashMap, USR_HM_PATH);
					System.out.println("New account created");
					clientID = msg[2];
					msg_sent = "OK";
					result = true;
				} else  {
					System.out.println("User already registered");
					msg_sent = "ACCOUNT EXISTS";
				}
				sendMsg(msg_sent.getBytes(), "AES");
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
					String hashedPass = hashPasswordSHA512(msg[3], msg[2]); //hashes password using username as salt
					beaconHashMap.put(msg[2], hashedPass);
					saveStatus(beaconHashMap, BCN_HM_PATH);
					System.out.println("New account created");
					clientID = msg[2];
					msg_sent = "OK";
					result = true;
				} else  {
					System.out.println("Beacon already registered, checking password...");
					String hashedPass = hashPasswordSHA512(msg[3], msg[2]); //hashes password using username as salt
					if(beaconHashMap.get(msg[2]).equals(hashedPass)) {
						System.out.println("Beacon logged in!");
						clientID = msg[2];
						msg_sent = "OK";
						result = true;
					} else System.out.println("Wrong Password!");
				}
				break;
			}

			sendMsg(msg_sent.getBytes("UTF-8"), "AES");
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
				byte[] rcvd_msg = rcvMsg("AES");
				if(rcvd_msg == null) break;

				//String[] msg = (new String(rcvd_msg, "UTF-8")).split(delim);

				switch(new String(rcvd_msg, "UTF-8")) {

				case "COORDS":
					//System.out.println("beacon sent " + msg[1] + " " + msg[2] + " coordinates");
					byte[] _coords = rcvMsg("AES");
					byte[] _iv = rcvMsg("AES");
					System.out.println("iv size: " + _iv.length);
					
					sendMsg("RECEIVED".getBytes("UTF-8"),"AES");

					//create directory to store coords
					File directory = new File("Coordinates");
					if(! directory.exists())
						directory.mkdir();

					//new file if one doesn't already exist
					File newFile = new File("Coordinates" + File.separator + "coords" + clientID + ".txt");
					newFile.createNewFile();
					FileOutputStream fos = new FileOutputStream(newFile);
					fos.write(_coords);
					fos.close();
					
					//new file if one doesn't already exist
					newFile = new File("Coordinates" + File.separator + "iv" + clientID + ".txt");
					newFile.createNewFile();
					fos = new FileOutputStream(newFile);
					fos.write(_iv);
					fos.close();
					break;

				default:
					break;
				}
			}
			System.out.println(" Ended Connection with Beacon " + clientID);
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
				byte[] rcvd_msg = rcvMsg("AES");
				if(rcvd_msg == null) break;

				String msg_rcv = new String(rcvd_msg, "UTF-8");
				//String msg_rcv = input.readLine();
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
					//output.writeBytes(msg_sent + '\n');
					sendMsg(msg_sent.getBytes(), "AES");
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

					//output.writeBytes(msg_sent + '\n');
					sendMsg(msg_sent.getBytes(), "AES");
					break;

					//case to request coords from a beacon
				case "REQ":
					//REQ_BEACONID
					System.out.println("App tried to request coords from beacon: " + msg[1]);
					loadHashMaps();
					//check if beacon was added
					ArrayList<String> beacons = appBeacons.get(clientID);
					if( (beacons != null) && (beacons.contains(msg[1])) ){
						//beacon was added
						//read from file 
						/*String aux;
						byte[] encoded = Files.readAllBytes(Paths.get("Coordinates"+ File.separator +"coords" + msg[1] + ".txt"));
						aux= new String(encoded, "UTF-8");
						sendMsg(aux.getBytes("UTF-8"), "AES");
						
						byte[] iv = Files.readAllBytes(Paths.get("Coordinates"+ File.separator +"iv" + msg[1] + ".txt"));
						
						aux= new String(encoded, "UTF-8");
						sendMsg(aux.getBytes("UTF-8"), "AES");
						System.out.println("iv size: " + aux.getBytes("UTF-8").length);*/
						
						
						File file = new File("Coordinates"+ File.separator +"coords" + msg[1] + ".txt");
						FileInputStream fis = new FileInputStream(file);
						byte[] _coords = new byte[fis.available()];
						fis.read(_coords);
						fis.close();
						
						
						file = new File("Coordinates"+ File.separator +"iv" + msg[1] + ".txt");
						fis = new FileInputStream(file);
						byte[] _iv = new byte[fis.available()];
						fis.read(_iv);
						fis.close();
						
						System.out.println("iv size: " + _iv.length);
						
						sendMsg(_coords,"AES");
						sendMsg(_iv,"AES");
						break;
					}
					//output.writeBytes(msg_sent + '\n');
					sendMsg(msg_sent.getBytes("UTF-8"), "AES");
					break;

				default:
					System.out.println("Operation Denied");
					output.writeBytes(msg_sent + '\n');
					break;
				}
			}	
			System.out.println("Connection with Client " + clientID +" Closed!");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	//#################################CIPHER OPERATIONS#############################################

	private byte[] generateMac (byte[] msg) {
		byte[] mac_data = null;
		try {
			Mac sha512Mac = Mac.getInstance("HmacSHA512");
			sha512Mac.init(sk);
			mac_data = sha512Mac.doFinal(msg);
			System.out.println("-----HMAC Length----- " + mac_data.length);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
		}

		return mac_data;
	}

	private void sendMsg(byte[] msg, String type) {
		//TODO: Add counter, signature, SALT(?), etc...
		try {
			byte[] send_msg = encrypt(msg, type);
			if(type.equals("AES")) {
				byte[] hmac = generateMac(send_msg);
				output.write(hmac);
			} 
			output.writeInt(send_msg.length);
			output.write(send_msg);

			System.out.println("ORIGINAL: ");
			System.out.println( new String(msg, "UTF-8"));
			System.out.println("ENCRYPTED: ");
			System.out.println(new String(send_msg, "UTF-8"));
		} catch (IOException e) {
			System.out.println("Send Message: FAIL");
		}
	}

	private byte[] rcvMsg(String type) {
		byte[] msg = null;
		//TODO: confirm counter, signature and isolate the message
		try {
			byte[] rcvd_hmac = null;
			if(type.equals("AES")) {
				rcvd_hmac = new byte[64];
				input.read(rcvd_hmac, 0, 64);
			}
			byte[] rcvd_msg = new byte[input.readInt()];
			input.readFully(rcvd_msg);
			if(type.equals("AES")) {
				byte[] hmac = generateMac(rcvd_msg);
				if(!Arrays.equals(hmac, rcvd_hmac))
					return null;
			}
			msg = decrypt(rcvd_msg, type);

			System.out.println("RECEIVED: ");
			System.out.println(new String(rcvd_msg, "UTF-8"));
			System.out.println("DECRYPTED: ");
			System.out.println(new String(msg, "UTF-8"));
		} catch (IOException e) {
			System.out.println("Receive Message: FAIL");
		}
		return msg;
	}

	private byte[] encrypt(byte[] msg, String type) {
		byte[] result = null;

		switch(type) {
		case"RSA":
			try {
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, cli_pubkey);
				result = cipher.doFinal(msg);
			} catch (InvalidKeyException  | IllegalBlockSizeException
					| BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
				System.out.println("Encryption: FAILED");
				e.printStackTrace();
			}
			break;

		case"AES":
			try {
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, sk, new IvParameterSpec(iv));
				result = cipher.doFinal(msg);

				//generateIV for next communication
				generateIV(result);

			} catch (InvalidKeyException | InvalidAlgorithmParameterException 
					| NoSuchAlgorithmException | NoSuchPaddingException 
					| IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}
			break;
		}
		return result;
	}

	private byte[] decrypt(byte[] msg, String type) {
		byte[] result = null;

		switch(type) {
		case"RSA":
			try {
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.DECRYPT_MODE, server_privkey);
				result = cipher.doFinal(msg);
			} catch (InvalidKeyException | IllegalBlockSizeException
					| BadPaddingException | NoSuchAlgorithmException 
					| NoSuchPaddingException e) {
				System.out.println("Decryption: FAILED");
			}
			break;
		case"AES":
			try {	
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));
				result = cipher.doFinal(msg);

				//generateIV for next communication
				generateIV(msg);

			} catch (InvalidKeyException | InvalidAlgorithmParameterException 
					| NoSuchAlgorithmException | NoSuchPaddingException 
					| IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}
			break;
		}

		return result;
	}

	private void generateIV(byte[] msg) {
		if(iv.length <= 0){
			SecureRandom random = new SecureRandom();
			iv = new byte [16];
			random.nextBytes(iv);
		} else {
			iv = Arrays.copyOfRange(msg, msg.length-16, msg.length);
		}
	}

	//#################################HASH-MAPS#####################################################
	@SuppressWarnings({ "rawtypes", "unchecked" })
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
