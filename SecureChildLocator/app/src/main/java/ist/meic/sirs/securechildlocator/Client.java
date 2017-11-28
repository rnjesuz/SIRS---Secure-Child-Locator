package ist.meic.sirs.securechildlocator;

import android.util.Log;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import ist.meic.sirs.securechildlocator.exceptions.*;

/**
 * Created by pedro on 11/11/2017.
 */

public class Client {

    private static Client instance = null;

    private static String server_ip;
    private static int server_port;
    private BufferedReader input;
    private DataOutputStream output;
    private Socket socket;

    private final String delim = "_";

    protected Client() {}

    public static synchronized Client getInstance() {
        if(null == instance){
            instance = new Client();
            instance.server_ip = "192.168.1.7";
            instance.server_port = 6667;
        }
        return instance;
    }

    public DataOutputStream getOutput() {
        return output;
    }

    public BufferedReader getInput() {
        return input;
    }

    public Socket getSocket() {
        return socket;
    }

    public void setOutput(Socket s) {
        try {
            output = new DataOutputStream(s.getOutputStream());
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    public void setInput(Socket s) {
        try {
            input =  new BufferedReader(new InputStreamReader(s.getInputStream()));
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    public void setSocket() {
        try {
            socket = new Socket(server_ip, server_port);
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    public void connectToServer() {
        Log.d("CLIENT", "Connecting to server...\n");
        setSocket();
        setInput(getSocket());
        setOutput(getSocket());
        Log.d("CLIENT", "Connection Established!\n");
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

        if (msg.equals("OK")) {
            Log.d("CLIENT", "Logged in!");
            return;
        }

        if (msg.equals("WRONG PASS")) {
            Log.d("CLIENT", "Wrong Password, try again...");
            throw new IncorrectPasswordException();
        }

        if (msg.equals("NOT REGISTERED")) {
            Log.d("CLIENT", "Account doesn't exist, please sign up...");
            throw new AccountDoesntExistException();
        }

        if (msg.equals("NO")) {
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

        if (msg.equals("OK")) {
            Log.d("CLIENT", "Logged in!");
            return;
        }

        if (msg.equals("ACCOUNT EXISTS")) {
            Log.d("CLIENT", "Account already exists");
            throw new AccountAlreadyExistsException();
        }

        if (msg.equals("NO")) {
            Log.d("CLIENT", "Access Denied.");
            throw new ConnectionFailedException();
        }
    }

    public void addBeacon(String id, String pass) throws ConnectionFailedException, IncorrectPasswordException,
            BeaconDoesntExistException, BeaconAlreadyAddedException {
        String msg;

        try {
            Log.d("CLIENT", "Adding Beacon " + id);
            output.writeBytes("ADD" + delim + id + delim + pass + '\n');
            msg = input.readLine();
        } catch (IOException e) {
            Log.d("CLIENT", e.getMessage());
            throw new ConnectionFailedException();
        }

        if (msg.equals("OK")) {
            Log.d("CLIENT", "Beacon added");
            return;
        }

        if (msg.equals("ALREADY ADDED")) {
            Log.d("CLIENT", "Beacon already added to list...");
            throw new BeaconAlreadyAddedException();
        }

        if (msg.equals("DOESNT EXIST")) {
            Log.d("CLIENT", "Beacon doesn't exist...");
            throw new BeaconDoesntExistException();
        }

        if (msg.equals("NO")) {
            Log.d("CLIENT", "Wrong Password, Access Denied.");
            throw new IncorrectPasswordException();
        }
    }

    public ArrayList<String> getList() throws ConnectionFailedException, ListDoesntContainElementsException {
        String rcv;
        String[] msg;
        ArrayList<String> list = new ArrayList<String>();

        try {
            Log.d("CLIENT", "Requesting List of beacons that the client has...");
            output.writeBytes("LIST" + '\n');
            rcv = input.readLine();
            Log.d("CLIENT", "Received the following: " + rcv);

            if(rcv.equals("NO")) {
                Log.d("CLIENT", "list doesn't contain elements");
                throw new ListDoesntContainElementsException();
            }

            msg = rcv.split(delim);

            for(String beacon : msg) {
                list.add(beacon);
                Log.d("CLIENT", beacon);
            }

        } catch (IOException e) {
            Log.d("CLIENT", e.getMessage());
            throw new ConnectionFailedException();
        }

        return list;
    }

    public String getCoordinates(String beaconID) {
        String coords = "";

        try {
            output.writeBytes("REQ" + delim + beaconID + '\n');
            coords = input.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return coords;
    }
}

