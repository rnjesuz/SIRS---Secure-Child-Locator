import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by pedro on 11/11/2017.
 */

public class Client {

	private static Client instance = null;

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

	private final String delim = "_";

	public Client() {
		server_ip="localhost";
		server_port=6667;
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
		//ASSTEST();
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

	/*private void ASSTEST() {
		String msg = "how's dat ass?";
		try {
			sendMsg(msg.getBytes("UTF-8"), "RSA");
			rcvMsg("RSA");
			System.out.println("ASS DONE");
		} catch (UnsupportedEncodingException e) {
			System.out.println( "ASS FAILED");
		}
	}*/

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

	public void login(String email, String password) {
		String msg = "NO";

		try {
			System.out.println("Logging in with " + email + " " + password);
			String sendmsg = "APP" + delim + "LOGIN" + delim + email + delim + password;
			sendMsg(sendmsg.getBytes("UTF-8"), "AES");
			msg = new String(rcvMsg("AES"),"UTF-8");
		} catch(IOException e) {

		}

		if(msg.isEmpty()) {
			//the message being empty, means that there was an error in the encryption
			//THROW NEW EXCEPTION? ex. CipherErrorException
			return;
		}

		if (msg.equals("OK")) {
			System.out.println("Log In: SUCCESS");
			return;
		}

		if (msg.equals("WRONG PASS")) {
			System.out.println("Wrong Password, try again...");
			//throw new IncorrectPasswordException();
		}

		if (msg.equals("NOT REGISTERED")) {
			System.out.println("Account doesn't exist, please sign up...");
			//throw new AccountDoesntExistException();
		}

		if (msg.equals("NO")) {
			System.out.println("Access Denied.");
			//throw new ConnectionFailedException();
		}
	}

	public void signUp(String email, String password) {
		String msg = "NO";

		try{
			System.out.println("Signing in with " + email + " " + password);
			String sendmsg = "APP" + delim + "SIGNUP" + delim + email + delim + password;
			sendMsg(sendmsg.getBytes("UTF-8"), "AES");
			msg = new String(rcvMsg("AES"),"UTF-8");
		} catch(IOException e) {

		}

		if (msg.equals("OK")) {
			System.out.println("Logged in!");
			return;
		}

		if (msg.equals("ACCOUNT EXISTS")) {
			System.out.println("Account already exists");
			//throw new AccountAlreadyExistsException();
		}

		if (msg.equals("NO")) {
			System.out.println("Access Denied.");
			//throw new ConnectionFailedException();
		}
	}

	public void addBeacon(String id, String pass) {
		String msg = "NO";

		try {
			System.out.println("Adding Beacon " + id);
			String hashedPass = hashPasswordSHA512(pass, id);
			String sendmsg = "ADD" + delim + id + delim + hashedPass;
			sendMsg(sendmsg.getBytes("UTF-8"), "AES");
			msg = new String(rcvMsg("AES"),"UTF-8");
		} catch (IOException e) {
			System.out.println(e.getMessage());
			//throw new ConnectionFailedException();
		}

		if (msg.equals("OK")) {
			System.out.println("Beacon added");
			return;
		}

		if (msg.equals("ALREADY ADDED")) {
			System.out.println("Beacon already added to list...");
			//throw new BeaconAlreadyAddedException();
		}

		if (msg.equals("DOESNT EXIST")) {
			System.out.println("Beacon doesn't exist...");
			//throw new BeaconDoesntExistException();
		}

		if (msg.equals("NO")) {
			System.out.println("Wrong Password, Access Denied.");
			//throw new IncorrectPasswordException();
		}
	}

	public ArrayList<String> getList() {
		String rcv;
		String[] msg;
		ArrayList<String> list = new ArrayList<String>();

		try {
			System.out.println("Requesting List of beacons that the client has...");
			output.writeBytes("LIST" + '\n');
			rcv = input.readLine();
			System.out.println("Received the following: " + rcv);

			if(rcv.equals("NO")) {
				System.out.println("list doesn't contain elements");
				//throw new ListDoesntContainElementsException();
			}

			msg = rcv.split(delim);

			for(String beacon : msg) {
				list.add(beacon);
				System.out.println(beacon);
			}

		} catch (IOException e) {
			System.out.println(e.getMessage());
			//throw new ConnectionFailedException();
		}

		return list;
	}

	public String getCoordinates(String beaconID) {
		String coords = "";

		try {
			output.writeBytes("REQ" + delim + beaconID + '\n');
			coords = input.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return coords;
	}

	private void sendMsg(byte[] msg, String type) {
		//TODO: Add counter, signature, SALT(?), etc...
		try {
			byte[] send_msg = encrypt(msg, type);
			output.writeInt(send_msg.length);
			output.write(send_msg);
			System.out.println("ORIGINAL: " + new String(msg, "UTF-8"));
			System.out.println("ENCRYPTED: " + new String(send_msg, "UTF-8"));
		} catch (IOException e) {
			System.out.println( "Send Message: FAIL");
			//throw new ConnectionFailedException();
		}
	}

	private byte[] rcvMsg(String type) {
		byte[] msg = null;
		//TODO: confirm counter, signature and isolate the message
		try {
			byte[] rcvd_msg = new byte[input.readInt()];
			input.readFully(rcvd_msg);
			msg = decrypt(rcvd_msg, type);
			System.out.println("RECEIVED: " + new String(rcvd_msg, "UTF-8"));
			System.out.println( "DECRYPTED: " + new String(msg, "UTF-8"));
		} catch (IOException e) {
			System.out.println("Receive Message: FAIL");
			//throw new ConnectionFailedException();
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
}

