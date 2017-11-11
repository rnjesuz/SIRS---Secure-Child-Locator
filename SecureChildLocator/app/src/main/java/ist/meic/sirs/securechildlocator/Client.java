package ist.meic.sirs.securechildlocator;

import android.util.Log;
import java.io.*;
import java.net.*;

/**
 * Created by pedro on 11/11/2017.
 */

public class Client {

    private static final String server_ip = "192.168.1.6";
    private static final int server_port = 6667;
    private BufferedReader input;
    private DataOutputStream output;
    private Socket socket;

    public Client() {}

    public void connectToServer() throws ConnectionFailedException {
        try {
            Log.d("CLIENT", "Connecting to server...\n");

            socket = new Socket();
            socket.bind(null);
            socket.connect((new InetSocketAddress(server_ip, server_port)), 100000);

            Log.d("CLIENT", "Connection Established!\n");
            output = new DataOutputStream(socket.getOutputStream());
            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e) {
            Log.d("CLIENT", e.getMessage());
            throw new ConnectionFailedException();
        }
    }

    public void login(String email, String password) throws ConnectionFailedException, IncorrectPasswordException {
        String response = " ";

        try {
            Log.d("CLIENT", "Logging in with " + email + " " + password);
            output.writeBytes("LOGIN_" + email + "_" + password + '\n');
            response = input.readLine();
        } catch (IOException e) {
            Log.d("CLIENT", e.getMessage());
            throw new ConnectionFailedException();
        }

        if(response.equals("OK")) {
            Log.d("CLIENT", "Logged in!");
            return;
        } else throw new IncorrectPasswordException();
    }
}
