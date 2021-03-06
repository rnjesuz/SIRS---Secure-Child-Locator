import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

/**
 * Created by pedro on 11/11/2017.
 */

public class Client {
	private PrivateKey cli_privkey;
	private PublicKey cli_pubkey;
	private PublicKey server_pubkey;
	private SecretKey sk;
	private byte[] iv;
	private Cipher cipher;

	private static String server_ip;
	private static int server_port;
	private DataInputStream input;
	private DataOutputStream output;
	private Socket socket;

	private HashMap<String, String> beaconHashMap = new HashMap<String, String>();

	private final String BCN_HM_PATH = "/database_app/beaconHashMap.dat";

	private final String delim = "_";

	public Client() {
		server_ip="localhost";
		server_port=6667;

        final String dir = System.getProperty("user.dir");
        File file = new File(dir + "/database_app");
        if(!file.exists()) {
            file.mkdir();
        }

        loadHashMaps();
	}

	public DataOutputStream getOutput() {
		return output;
	}

	public DataInputStream getInput() {
		return input;
	}

	public Socket getSocket() {
		return socket;
	}

	public void setOutput(Socket s) {
		try {
			output = new DataOutputStream(s.getOutputStream());
		} catch(IOException e) {
			e.printStackTrace();
		}
	}

	public void setInput(Socket s) {
		try {
			input =  new DataInputStream(s.getInputStream());
		} catch(IOException e) {
			e.printStackTrace();
		}
	}

	public void setSocket() {
		try {
			socket = new Socket(server_ip, server_port);
			//socket.setSoTimeout(1000);
		} catch(IOException e) {
			e.printStackTrace();
		}
	}

	public void connectToServer() {
		System.out.println("Connecting to server...");
		setSocket();
		setInput(getSocket());
		setOutput(getSocket());
		generateKeyPair();
		tradeKeys();
		rcvSessionKey();
		System.out.println("Connection Established!");
	}

	//Generate Asymmetric Key pair
	private void generateKeyPair() {
		System.out.println("Generating Key Pair");
		try {
			KeyPairGenerator keyPairGenerator = null;
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			cli_pubkey = keyPair.getPublic();
			cli_privkey = keyPair.getPrivate();
			System.out.println("Key Pair Generation: SUCCESS");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Key Pair Generation: FAIL");
		}
	}

	private void tradeKeys() {
		//Send public key to server
		try {
			output.writeInt(cli_pubkey.getEncoded().length);
			output.write(cli_pubkey.getEncoded());
			output.flush();
			System.out.println("Sent Public Key!");

			byte[] encoded_serverpub = new byte[input.readInt()];
			input.readFully(encoded_serverpub);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded_serverpub);
			server_pubkey = keyFactory.generatePublic(publicKeySpec);
			System.out.println("Server Public Key saved");

		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println("Client Public Key wasn't delivered");
		}
	}

	private void rcvSessionKey() {

		try {
			int ivSize = 16;
			byte[] msg = new byte[input.readInt()];
			input.readFully(msg);

			iv = new byte[ivSize];
			System.arraycopy(msg, 0, iv, 0, ivSize);

			byte[] encrypted = new byte[msg.length - ivSize];
			System.arraycopy(msg, ivSize, encrypted, 0, encrypted.length);
			sk = new SecretKeySpec(decrypt(encrypted, "RSA"), "AES");

			sendMsg("OK".getBytes("UTF-8"),  "AES");

		} catch (IOException e) {

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
			System.out.println("Password wasn't hashed");
		}
		return hashedPass;
	}

	public String login(String email, String password) {
		String msg = "NO";

		try {
			System.out.println("Logging in with " + email + " " + password);
			//String hashedPass = hashPasswordSHA512(password, email);
			String sendmsg = "APP" + delim + "LOGIN" + delim + email + delim + password;
			sendMsg(sendmsg.getBytes("UTF-8"), "AES");
			msg = new String(rcvMsg("AES"),"UTF-8");
		} catch(IOException e) {

		}

		if(msg == null || msg.isEmpty()) {
			//the message being empty, means that there was an error in the encryption
			//THROW NEW EXCEPTION? ex. CipherErrorException
			System.out.println("====================");
			System.out.println("Log In: ERROR");
			System.out.println("====================");
			msg = "EMPTY";
		}

		if (msg.equals("OK")) {
			System.out.println("====================");
			System.out.println("Log In: SUCCESS");
			System.out.println("====================");
		}

		if (msg.equals("WRONG PASS")) {
			System.out.println("====================");
			System.out.println("Error logging in.");
			System.out.println("====================");
			//throw new IncorrectPasswordException();
		}

		if (msg.equals("NOT REGISTERED")) {
			System.out.println("====================");
			System.out.println("Error logging in.");
			System.out.println("====================");
			//throw new AccountDoesntExistException();
		}

		if (msg.equals("NO")) {
			System.out.println("====================");
			System.out.println("Access Denied.");
			System.out.println("====================");
			//throw new ConnectionFailedException();
		}
		
		return msg;
	}

	public String signUp(String email, String password) {
		String msg = "NO";

		try{
			System.out.println("Signing in with " + email + " " + password);
			String sendmsg = "APP" + delim + "SIGNUP" + delim + email + delim + password;
			sendMsg(sendmsg.getBytes("UTF-8"), "AES");
			msg = new String(rcvMsg("AES"),"UTF-8");
		} catch(IOException e) {

		}

		if(msg == null || msg.isEmpty()) {
			//the message being empty, means that there was an error in the encryption
			//THROW NEW EXCEPTION? ex. CipherErrorException
			System.out.println("====================");
            System.out.println("Request Failed");
			System.out.println("====================");
			msg="EMPTY";
		}

		if (msg.equals("OK")) {
			System.out.println("====================");
			System.out.println("Signed Up!");
			System.out.println("====================");
		}

		if (msg.equals("ACCOUNT EXISTS")) {
			System.out.println("====================");
			System.out.println("Account already exists");
			System.out.println("====================");
			//throw new AccountAlreadyExistsException();
		}

		if (msg.equals("NO")) {
			System.out.println("====================");
			System.out.println("Access Denied.");
			System.out.println("====================");
			//throw new ConnectionFailedException();
		}
		
		return msg;
	}

	public void addBeacon(String id, String pass) {
		String msg = "NO";
        String hashedPass = null;

		try {
			System.out.println("Adding Beacon " + id);
			hashedPass = hashPasswordSHA512(pass, id);
			String sendmsg = "ADD" + delim + id + delim + hashedPass;
			sendMsg(sendmsg.getBytes("UTF-8"), "AES");
			msg = new String(rcvMsg("AES"),"UTF-8");
		} catch (IOException e) {
			//System.out.println(e.getMessage());
			//throw new ConnectionFailedException();
		}

		if(msg == null || msg.isEmpty()) {
			//the message being empty, means that there was an error in the encryption
			//THROW NEW EXCEPTION? ex. CipherErrorException
			System.out.println("====================");
            System.out.println("Request Failed");
			System.out.println("====================");
			msg="EMPTY";
		}

		if (msg.equals("OK")) {
			loadHashMaps();
            beaconHashMap.put(id, pass);
            saveStatus(beaconHashMap, BCN_HM_PATH);

			System.out.println("====================");
			System.out.println("Beacon added!");
			System.out.println("====================");
			return;
		}

		if (msg.equals("ALREADY ADDED")) {
			System.out.println("====================");
			System.out.println("Beacon already added to list...");
			System.out.println("====================");
			//throw new BeaconAlreadyAddedException();
		}

		if (msg.equals("DOESNT EXIST")) {
			System.out.println("====================");
			System.out.println("Beacon doesn't Exist");
			System.out.println("====================");
			//throw new BeaconDoesntExistException();
		}

		if (msg.equals("NO")) {
			System.out.println("====================");
			System.out.println("Operation Denied");
			System.out.println("====================");
			//throw new IncorrectPasswordException();
		}
	}

	public void getList() {
		String rcv;
		String[] msg;

		try {
			System.out.println("Requesting List of beacons that the client has...");
			//output.writeBytes("LIST" + '\n');
			String sendmsg = "LIST";
			sendMsg(sendmsg.getBytes("UTF-8"), "AES");
			//rcv = input.readLine();
			rcv = new String(rcvMsg("AES"),"UTF-8");
			System.out.println("Received the following: " + rcv);

            if(rcv == null || rcv.isEmpty()) {
                //the message being empty, means that there was an error in the encryption
                //THROW NEW EXCEPTION? ex. CipherErrorException
                System.out.println("====================");
                System.out.println("Request Failed");
                System.out.println("====================");
                rcv = "EMPTY";
            }
			
			if(rcv.equals("NO")) {
				System.out.println("====================");
				System.out.println("No beacons added...");
				System.out.println("====================");
				//throw new ListDoesntContainElementsException();
			}
			else {
				msg = rcv.split(delim);
	
				System.out.println("====================");
				System.out.println("You have added the following beacons: ");
				for(String beacon : msg) {
					System.out.println(beacon);
				}
				System.out.println("====================");
			}

		} catch (IOException e) {
			System.out.println("====================");
			System.out.println("Request Failed");
			System.out.println("====================");
			
		}
	}

	public String getCoordinates(String beaconID) {
		String coords = "";

		try {
			//output.writeBytes("REQ" + delim + beaconID + '\n');	
			loadHashMaps();
			if(beaconHashMap.containsKey(beaconID)) {
				String pass = beaconHashMap.get(beaconID);
				String sendmsg = "REQ" + delim + beaconID;
				sendMsg(sendmsg.getBytes("UTF-8"), "AES");
				byte[] _coords = rcvMsg("AES");
				byte[] _iv = rcvMsg("AES");
				coords = decipherWithPass(_coords, pass, _iv);
			}
			
			if(coords != null && !coords.equals("NO")){
				System.out.println("====================");
				System.out.println("The beacon " + beaconID + " is at the following coordinates: " + coords);
				System.out.println("====================");
				}
			else{
				System.out.println("====================");
				System.out.println("Coordinates not available");
				System.out.println("====================");
				}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return coords;
	}

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
			System.out.println("ORIGINAL: " + new String(msg, "UTF-8"));
			System.out.println("ENCRYPTED: " + new String(send_msg, "UTF-8"));
		} catch (IOException e) {
			System.out.println( "Send Message: FAIL");
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
			System.out.println("RECEIVED: " + new String(rcvd_msg, "UTF-8"));
			System.out.println( "DECRYPTED: " + new String(msg, "UTF-8"));
		} catch (IOException e) {
			System.out.println("Receive Message: FAIL");
		}
		return msg;
	}

	private byte[] encrypt(byte[] msg, String type) {
		byte[] result = null;

		switch(type) {
		case "RSA":
			try {
				cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, server_pubkey);
				result = cipher.doFinal(msg);
			} catch (InvalidKeyException  | IllegalBlockSizeException
					| BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
				System.out.println("Encryption: FAILED");
				e.printStackTrace();
			}
		case "AES":
			try {
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, sk, new IvParameterSpec(iv));
				result = cipher.doFinal(msg);
				//generateIV for next communication
				generateIV(result);
			} catch (InvalidKeyException
					| IllegalBlockSizeException
					| BadPaddingException | NoSuchAlgorithmException 
					| NoSuchPaddingException | InvalidAlgorithmParameterException e) {
				System.out.println("Encryption: FAILED");
				e.printStackTrace();
			}
		}

		return result;
	}

	private byte[] decrypt(byte[] msg, String type) throws IOException {
		byte[] result = null;

		switch(type) {
		case"RSA":
			try {
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.DECRYPT_MODE, cli_privkey);
				result = cipher.doFinal(msg);
			} catch (InvalidKeyException | IllegalBlockSizeException
					| BadPaddingException | NoSuchAlgorithmException
					| NoSuchPaddingException e) {
				System.out.println("Decryption: FAILED");
				e.printStackTrace();
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
					| IllegalBlockSizeException | BadPaddingException 
					| NoSuchAlgorithmException 
					| NoSuchPaddingException e) {
				System.out.println("Decryption: FAILED");
				e.printStackTrace();
			}			
			break;
		}

		return result;
	}

	private void generateIV(byte[] msg) {
		iv = Arrays.copyOfRange(msg, msg.length-16, msg.length);
	}

	//#################################HASH-MAPS#####################################################
	@SuppressWarnings({ "unchecked", "rawtypes" })
	private void loadHashMaps() {
		final String dir = System.getProperty("user.dir");
		System.out.println("Loading hashmaps...");

		File file = new File(dir + BCN_HM_PATH);
		if(file.exists()) {
			beaconHashMap = (HashMap) loadStatus(BCN_HM_PATH);
			System.out.println("Beacon hashmap loaded!");
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
	
	/*private String decipherPass(byte[] cipherText, String Beaconpassword){
		String plainText = "";
		try{
			SecretKeySpec keySpec = null;
			keySpec = new SecretKeySpec(Beaconpassword.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			plainText = new String (cipher.doFinal(cipherText), "UTF-8");
		} //TODO wrong! wrong! wrong!
		catch (Exception e){
			e.printStackTrace();
		}
		return plainText;
	}*/
	
	private String decipherWithPass(byte[] cipherText, String BeaconPassword, byte[] iv){

		String plainText = "";
		
		try{

			System.out.println(cipherText);

			//Generate SecretKey
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(BeaconPassword.toCharArray(), "salt".getBytes(), 65536, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
			//Decipher
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
			plainText = new String(cipher.doFinal(cipherText), "UTF-8");

			System.out.println(plainText);

		} //TODO wrong! wrong! wrong!
		catch (Exception e){
			e.printStackTrace();
		}
		return plainText;
	}
	
}

