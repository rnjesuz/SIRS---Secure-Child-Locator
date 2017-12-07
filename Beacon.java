import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.*;
import java.security.AlgorithmParameters;


import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

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
	private DataInputStream socketIn;
	private DataOutputStream socketOut;

	//asymmetric
	private PublicKey pub;
	private PrivateKey priv;
	private PublicKey server_pub;

	//symmetric
	private byte[] iv;
	private SecretKey sk;


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

		generateKeyPair();
		ConnectToServer();
		tradeKeys();
		//ASSTEST();
		rcvSessionKey();
		SignUp();
		ImAliveCicle();
	}

	private void generateKeyPair() {

		KeyPairGenerator keyPairGenerator = null;

		try {

			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			pub = keyPair.getPublic();
			priv = keyPair.getPrivate();

			//Save the keys to files
			/*File directory = new File("BeaconDir");
			if(! directory.exists())
				directory.mkdir();

			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pub.getEncoded());
			FileOutputStream fos = new FileOutputStream("BeaconDir/pubkey");
			fos.write(x509EncodedKeySpec.getEncoded());
			fos.close();*/
			System.out.println("Key Pair Generation: SUCCESS");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Key Pair Generation: FAIL");
		}
	}

	private void ConnectToServer(){
		try {
			String ipToConnect=getIp();
			int portToConnect=getPort(); 
			System.out.println("Connecting to " + ipToConnect + " at port " + portToConnect);

			beaconSocket = new Socket(ipToConnect, portToConnect);
			socketOut = new DataOutputStream(beaconSocket.getOutputStream());
			socketIn = new DataInputStream(beaconSocket.getInputStream());
			System.out.println("Connection established");
		} catch (IOException e){
			e.printStackTrace();
		}
	}

	private void tradeKeys() {
		try {
			//get public key from file
			/*FileInputStream fis = new FileInputStream("BeaconDir/pubkey");
			byte[] beacon_encodedpubkey = new byte[fis.available()];
			fis.read(beacon_encodedpubkey);
			fis.close();*/

			//send public key to server
			System.out.println("Sending Beacon Public Key...");
			//System.out.println(new String(beacon_encodedpubkey, "UTF-8"));
			System.out.println(new String(pub.getEncoded(), "UTF-8"));
			
			socketOut.writeInt(pub.getEncoded().length);
			socketOut.write(pub.getEncoded());
			socketOut.flush();
			System.out.println("Sent Beacon Public Key");

			//get server public key from server
			System.out.println("Getting server public key");
			//FileOutputStream fos = new FileOutputStream("BeaconDir/serverpubkey");
			byte[] server_encodedpubkey = new byte[socketIn.readInt()];
			socketIn.readFully(server_encodedpubkey);
			/*byte[] aux = new byte[16 * 1024];
            int count;*/

			/*fos.write(server_encodedpubkey, 0, server_encodedpubkey.length);
			fos.close();*/
			System.out.println("Got server public key!");
			//System.out.println(new String(server_encodedpubkey, "UTF-8"));

            /*File filePublicKey = new File("BeaconDir/serverpubkey");
            fis = new FileInputStream("BeaconDir/serverpubkey");
            server_encodedpubkey = new byte[(int) filePublicKey.length()];
            fis.read(server_encodedpubkey);
            fis.close();*/

			//transform bytes to key
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(server_encodedpubkey);
			server_pub = keyFactory.generatePublic(publicKeySpec);
			System.out.println("Server Public Key saved");

		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}

	/*private void ASSTEST() {
		try {
			String msg = "How's dat ass?";
			sendMsg(msg.getBytes("UTF-8"), "RSA");		
			rcvMsg("RSA");
		} catch (UnsupportedEncodingException e) {
			System.out.println("NO ASS");
		}
	}*/
	
	private void rcvSessionKey() {
		
		try {
			int ivSize = 16; 
			byte[] msg = new byte[socketIn.readInt()];
			socketIn.readFully(msg);
			
			//NOTE: msg = iv + {sk}pub
			
			//get iv from msg
			iv = new byte[ivSize];
			System.arraycopy(msg,  0, iv, 0, ivSize);
			
			//get key from message
			byte[] encrypted = new byte[msg.length - ivSize];
			System.arraycopy(msg, ivSize, encrypted, 0, encrypted.length);
			sk = new SecretKeySpec(decrypt(encrypted, "RSA"), "AES");
			
			System.out.println("IV: " + new String(iv, "UTF-8"));
			System.out.println("Session Key: " + new String(sk.getEncoded(), "UTF-8"));
			
			//SEND ACK
			sendMsg("OK".getBytes("UTF-8"), "AES");	
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void SignUp() {
		System.out.println("Signing Up");
		try {
			String msg = "BEACON_SIGNUP_" + getUsername() + "_" + getPassword();
			sendMsg(msg.getBytes("UTF-8"), "AES");
			rcvMsg("AES");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void ImAliveCicle(){
		while(true){
			System.out.println("Sending coords...");
			try {
				//TODO change to a proper coordinates system
				String istCoords = "38.736685_-9.138619";  // latitude/longitude of IST. to simulate real coordinates
				String msg = "COORDS_" + istCoords;
				sendMsg(msg.getBytes("UTF-8"), "AES");

				byte[] received = rcvMsg("AES");
                if(received == null) continue;
				System.out.println(new String(received, "UTF-8"));
				//sleep for 10 seconds
				Thread.sleep(10000);
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InterruptedException e){
				e.printStackTrace();
			}	
		}
	}

	//#############################ENCRYPTION-DECRYPTION OPERATIONS#############################
    
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
			System.out.println("Message: " + new String(msg, "UTF-8"));
			byte[] send_msg = encrypt(msg, type);
            if(type.equals("AES")) {
                byte[] hmac = generateMac(send_msg);
                socketOut.write(hmac);
            } 
			socketOut.writeInt(send_msg.length);
			socketOut.write(send_msg);
			
			System.out.println("Message Sent: ");
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
                socketIn.read(rcvd_hmac, 0, 64);
            }
			byte[] rcvd_msg = new byte[socketIn.readInt()];
			socketIn.readFully(rcvd_msg);
            if(type.equals("AES")) {
                byte[] hmac = generateMac(rcvd_msg);
                if(!Arrays.equals(hmac, rcvd_hmac))
                    return null;
            }
			
			System.out.println("Message Received: ");
			System.out.println(new String(rcvd_msg, "UTF-8"));
			
			msg = decrypt(rcvd_msg, type);
			System.out.println("Decrypted Received Message: " + new String(msg, "UTF-8"));			
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
				cipher.init(Cipher.ENCRYPT_MODE, server_pub);
				result = cipher.doFinal(msg);
			} catch (InvalidKeyException | IllegalBlockSizeException
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
				cipher.init(Cipher.DECRYPT_MODE, priv);
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
					| NoSuchAlgorithmException | NoSuchPaddingException 
					| IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}
			break;
		}

		return result;
	}
	
	private void generateIV(byte[] msg) {
		iv = Arrays.copyOfRange(msg, msg.length-16, msg.length);
	}

	/*private byte[] cipherPass(String text){
		byte[] cipherText = null;
		try{
			byte[] output = null;
			SecretKeySpec keySpec = null;
			keySpec = new SecretKeySpec(password.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			output = cipher.doFinal(text.getBytes());
		} //TODO wrong! wrong! wrong!
		catch (Exception e){
			e.printStackTrace();
		}

		return cipherText;
	}*/
	
	private ArrayList<byte[]> cipherWithPass(String text){

		ArrayList<byte[]> output = null;
		try{

			System.out.println("Before ciphering with pass: " + text);

			//generate cypher key given password and salt
			char[] passwordChar = password.toCharArray();
			byte[] saltByte = "salt".getBytes();
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(passwordChar, saltByte, 65536, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
			//Cipher
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			byte[] cipherText = cipher.doFinal(text.getBytes("UTF-8"));

			System.out.println("After ciphering with pass: " + cipherText);

			AlgorithmParameters params = cipher.getParameters();
			byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
			output.add(cipherText);
			output.add(iv);

			//test decription
			//decipherAES(cipherText, iv);

		} //TODO wrong! wrong! wrong!
		catch (Exception e){
			e.printStackTrace();
		}

		return output;
	}

	//test function tocheck if cypher/uncypher works
	/*private void decipherAES(byte[] cipherText, byte[] iv){

		try{

			System.out.println(cipherText);

			//Generate SecretKey
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(password.toCharArray(), "salt".getBytes(), 65536, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
			//Decipher
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
			String plainText = new String(cipher.doFinal(cipherText), "UTF-8");

			System.out.println(plainText);

		} //TODO wrong! wrong! wrong!
		catch (Exception e){
			e.printStackTrace();
		}
	}*/
	 
}
