import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

	private final String ip = "192.168.1.6";
	private final int port = 6667;
	private ServerSocket welcomeSocket;


	public Server(){
	}
	
	public void runServer() {
		System.out.println("Setting up server...");
		setup();
		listen();
	}

	private void setup() {
		try {
			welcomeSocket = new ServerSocket(port);

			System.out.println("Server connected to " + ip + " listening at port " + port);
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
				(new ServerThread(connectionSocket)).start();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}


