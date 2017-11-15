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

    private final String delim = "_";

    public Client() {}

    public void connectToServer() throws ConnectionFailedException {
        try {
            Log.d("CLIENT", "Connecting to server...\n");

            socket  = new Socket(server_ip, server_port);
            output = new DataOutputStream(socket.getOutputStream());
            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            Log.d("CLIENT", "Connection Established!\n");
        } catch (IOException e) {
            Log.d("CLIENT", e.getMessage());
            throw new ConnectionFailedException();
        }
    }

    public void login(String email, String password) throws ConnectionFailedException,
            IncorrectPasswordException, AccountDoesntExistException {
        String msg;

        try {
            Log.d("CLIENT", "Logging in with " + email + " " + password);
            output.writeBytes("APP" + delim + "LOGIN" + delim + email + delim + password + '\n');
            msg = input.readLine();
        } catch (IOException e) {
            Log.d("CLIENT", e.getMessage());
            throw new ConnectionFailedException();
        }

        if(msg.equals("OK")) {
            Log.d("CLIENT", "Logged in!");
            return;
        }

        if(msg.equals("WRONG PASS")) {
            Log.d("CLIENT", "Wrong Password, try again...");
            throw new IncorrectPasswordException();
        }

        if(msg.equals("NOT REGISTERED")) {
            Log.d("CLIENT", "Account doesn't exist, please sign up...");
            throw new AccountDoesntExistException();
        }

        if(msg.equals("NO")) {
            Log.d("CLIENT", "Access Denied.");
            throw new ConnectionFailedException();
        }
    }

    public void signUp(String email, String password) throws ConnectionFailedException, AccountAlreadyExistsException {
        String msg;

        try {
            Log.d("CLIENT", "Signing in with " + email + " " + password);
            output.writeBytes("APP" + delim + "SIGNUP" + delim + email + delim + password + '\n');
            msg = input.readLine();
        } catch (IOException e) {
            Log.d("CLIENT", e.getMessage());
            throw new ConnectionFailedException();
        }

        if(msg.equals("OK")) {
            Log.d("CLIENT", "Logged in!");
            return;
        }

        if(msg.equals("ACCOUNT EXISTS")) {
            Log.d("CLIENT", "Account already exists");
            throw new AccountAlreadyExistsException();
        }

        if(msg.equals("NO")) {
            Log.d("CLIENT", "Access Denied.");
            throw new ConnectionFailedException();
        }
    }
}
