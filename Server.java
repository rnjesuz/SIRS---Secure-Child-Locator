import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class Server {

	private final String ip = "192.168.1.6";
	private final int port = 6667;
	private ServerSocket welcomeSocket;
	
	private PrivateKey priv;
	private PublicKey pub;

	public Server(){
	}

	public void runServer() {
		System.out.println("Setting up server...");
		setup();
		//TODO: Launch thread that periodically refreshes asymmetric keys
		generateKeyPair();
		listen();
	}

	private void setup() {
		try {
			welcomeSocket = new ServerSocket(port);
			System.out.println("Server connected to " + ip + " listening at port " + port);

			final String dir = System.getProperty("user.dir");
			File file = new File(dir + "/database");
			if(!file.exists()) {
				file.mkdir();
			}
		} catch (IOException e) {
			System.out.println("Couldn't connect to port " + port);
			e.printStackTrace();
		}
	}

	private void listen() {

		Socket connectionSocket;

		while(true) {
			try {
				System.out.println("Server listening at port " + port);
				connectionSocket = welcomeSocket.accept();
				System.out.println("Attempted Connection...");
				System.out.println("Launching thread to handle connection...");
				(new ServerThread(connectionSocket, pub, priv)).start();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	//Generate Asymmetric Key pair
	//TODO: send to server.java and store keys in a keystore
	private void generateKeyPair() {
		
		KeyPairGenerator keyPairGenerator = null;
		
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			pub = keyPair.getPublic();
			priv = keyPair.getPrivate();

            //Save the keys to files
			File directory = new File("ServerDir");
			if(! directory.exists())
					directory.mkdir();
			
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pub.getEncoded());
            FileOutputStream fos = new FileOutputStream("ServerDir/pubkey");
            fos.write(x509EncodedKeySpec.getEncoded());
            fos.close();
            
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
    				priv.getEncoded());
    		fos = new FileOutputStream("ServerDir/privkey");
    		fos.write(pkcs8EncodedKeySpec.getEncoded());
    		fos.close();
    		
			System.out.println("Key Pair Generation: SUCCESS");
		} catch (NoSuchAlgorithmException | IOException e) {
			System.out.println("Key Pair Generation: FAIL");
		}
	}
}


