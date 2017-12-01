import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

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
			System.out.println("Key Pair Generation: SUCCESS");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Key Pair Generation: FAIL");
		}
	}
}


