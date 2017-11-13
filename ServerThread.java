import java.io.*;
import java.net.*;
import java.util.*;

public class ServerThread extends Thread{

	private Socket socket;
	private BufferedReader input;
	private DataOutputStream output;
	
	private HashMap<String, String> appHashMap = new HashMap<String, String>();
	private final String APP_HT_PATH = "/database/appHashMap.dat";

	public ServerThread(Socket s) {
		socket = s;
	}

	@Override
	public void run() {
		System.out.println("In server thread...");
		prepareDatabase();
		handleConnection();
	}
	
	private void prepareDatabase(){
		final String dir = System.getProperty("user.dir");
		System.out.println(dir + APP_HT_PATH);
		File file = new File(dir + APP_HT_PATH);
		if(file.exists()) {
			appHashMap = (HashMap) loadStatus(APP_HT_PATH);
		} 
	}

	private void handleConnection() {
		try {
			input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			output = new DataOutputStream(socket.getOutputStream());
		
			System.out.println("Waiting for client response...");

			String msg_rcv = input.readLine();
			System.out.println("Received: " + msg_rcv);

			String[] msg = msg_rcv.split("_");
			//DEFAULT RESPONSE
			String msg_sent = "NO";
			
			if(msg[0].equals("LOGIN")) {
				if(appHashMap.containsKey(msg[1])) {
					if(appHashMap.get(msg[1]).equals(msg[2])) {
						System.out.println("Logged In");
						msg_sent = "OK";
					} 
				} else {
					//SIGN UP
					System.out.println("NEW ACCOUNT: Signed up");
					appHashMap.put(msg[1], msg[2]);
					saveStatus(appHashMap, APP_HT_PATH);
					msg_sent = "OK";
				}
			} 

			output.writeBytes(msg_sent + '\n');
			System.out.println("Sent: " + msg_sent);

		} catch (IOException | NullPointerException e) {
			System.out.println("Client Disconnected...");
		}
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
}
