import java.io.*;
import java.net.Socket;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.*;
import javax.crypto.spec.PBEKeySpec;

import java.nio.file.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

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

    private PublicKey pub;
    private PrivateKey priv;
    private PublicKey server_pub;
	
	
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
		
		//test cipher
		//cipherAES("Hello");
		
		
        //generateKeyPair();
		ConnectToServer();
		
        prepareCommunication();
		SignUp();
		try{
		String received = socketIn.readLine();
		System.out.println(received);
		if(received.equals("OK"))			
			ImAliveCicle();
		} catch(IOException e){
			e.printStackTrace();
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

	private void prepareCommunication(){
        //Send server public key
        /*try {
            File beacon_pubkeyfile = new File("BeaconDir/pubkey");
            FileInputStream fis = new FileInputStream("BeaconDir/pubkey");
            byte[] beacon_encodedpubkey = new byte[(int) beacon_pubkeyfile.length()];
            fis.read(beacon_encodedpubkey);
            fis.close();
            System.out.println("Sending Beacon Public Key: " + beacon_encodedpubkey);
            socketOut.write(beacon_encodedpubkey);
            socketOut.flush();
            System.out.println("Sent Beacon Public Key");
        } catch (IOException e) {
            e.printStackTrace();
        }*/

        //Get server public key
        try {
			System.out.println("Getting server pub Key");
            
			//create dir
			File directory = new File("BeaconDir");
			if(! directory.exists())
					directory.mkdir();
				
            FileOutputStream fos = new FileOutputStream("BeaconDir/server_pubkey");

            int count;
			byte[] aux = new byte[16 * 1024];
            while((count = socketIn.read(aux)) > 0) {
                fos.write(aux, 0, count);
            }
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Load server public key
        try{
			System.out.println("Loading server pub Key");
				
            File filePublicKey = new File("BeaconDir/server_pubkey");
            FileInputStream fis = new FileInputStream("BeaconDir/server_pubkey");
            byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
            fis.read(encodedPublicKey);
            fis.close();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
            server_pub = keyFactory.generatePublic(publicKeySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

	private void SignUp() {
		System.out.println("Signing Up");
		try {
			socketOut.writeBytes("BEACON_SIGNUP_" + getUsername() + "_" + getPassword() + '\n');
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
				socketOut.writeBytes("COORDS_" + istCoords + '\n');
				
				String received = socketIn.readLine();
				System.out.println(received);
				//sleep for 10 seconds
				Thread.sleep(10000);
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InterruptedException e){
				e.printStackTrace();
			}	
			
		}
	}
	
	private byte[] cipherAES(String text){
	
		byte[] cipherText = null;
		try{
			
			System.out.println(text);
			
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
			cipherText = cipher.doFinal(text.getBytes("UTF-8"));
			
			System.out.println(cipherText);
			
			AlgorithmParameters params = cipher.getParameters();
			byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
			
			//test decription
			//decipherAES(cipherText, iv);
			
		} //TODO wrong! wrong! wrong!
		catch (Exception e){
			e.printStackTrace();
		}
		
		return cipherText;
	}
	
	//test function tocheck if cypher/uncypher works
	private void decipherAES(byte[] cipherText, byte[] iv){
		
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
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pub.getEncoded());
            FileOutputStream fos = new FileOutputStream("BeaconDir/pubkey");
            fos.write(x509EncodedKeySpec.getEncoded());
            fos.close();
			System.out.println("Key Pair Generation: SUCCESS");
		} catch (NoSuchAlgorithmException|IOException e) {
			System.out.println("Key Pair Generation: FAIL");
		}
	}
}
