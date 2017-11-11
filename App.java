import java.io.*;
import java.net.Socket;

public class App {
	

	public static void main(String[] args) {
		final String server_ip = "192.168.1.6";
		final int server_port = 6667;
		BufferedReader in;
		DataOutputStream out;
		
		String sentence;
		
		String modifiedSentence;
		in = new BufferedReader(new InputStreamReader(System.in));
		Socket clientSocket;
		try {
			System.out.println("Connecting to " + server_ip + " at port " + server_port);
			
			clientSocket = new Socket(server_ip, server_port);
			out = new DataOutputStream(clientSocket.getOutputStream());
			in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			
			System.out.println("Connection established");
			System.out.println("Write message to send: ");

			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			sentence = br.readLine();
			
			out.writeBytes(sentence + '\n');
			modifiedSentence = in.readLine();
			System.out.println("FROM SERVER: " + modifiedSentence);
			clientSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
}
