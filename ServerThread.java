
import java.io.*;
import java.net.Socket;

public class ServerThread extends Thread{

	private Socket socket;
	private BufferedReader input;
	private DataOutputStream output;

	private final String dEmail = "@";
	private final String dPass = "qwerty";

	public ServerThread(Socket s) {
		socket = s;
	}

	@Override
	public void run() {
		System.out.println("In server thread...");
		handleConnection();
	}

	private void handleConnection() {
		try {
			input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			output = new DataOutputStream(socket.getOutputStream());
			String msg_sent = "";
			System.out.println("Waiting for client response...");

			String msg_rcv = input.readLine();
			System.out.println("Received: " + msg_rcv);

			String[] msg = msg_rcv.split("_");
			
			for(String m : msg) {
				System.out.println(m);
			}

			if(msg[0].equals("LOGIN") && msg[1].equals(dEmail) && msg[2].equals(dPass)) {
				msg_sent = "OK";
				//ESTABLISH COMMUNICATION
			} else msg_sent = "NO";

			output.writeBytes(msg_sent + '\n');
			System.out.println("Sent: " + msg_sent);
			
		} catch (IOException | NullPointerException e) {
			System.out.println("Client Disconnected...");
		}
	}
}
