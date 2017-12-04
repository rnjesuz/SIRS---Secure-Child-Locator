package ist.meic.sirs.securechildlocator;

import android.util.Log;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import ist.meic.sirs.securechildlocator.exceptions.*;

/**
 * Created by pedro on 11/11/2017.
 */

public class Client {

    private static Client instance = null;

    private PrivateKey cli_privkey;
    private PublicKey cli_pubkey;
    private PublicKey server_pubkey;
    private Cipher cipher;

    private static String server_ip;
    private static int server_port;
    private DataInputStream input;
    private DataOutputStream output;
    private Socket socket;

    private final String delim = "_";

    protected Client() {}

    public static synchronized Client getInstance() {
        if(null == instance){
            instance = new Client();
            instance.server_ip = "192.168.1.117";
            instance.server_port = 6667;
        }
        return instance;
    }

    public DataOutputStream getOutput() {
        return output;
    }

    public DataInputStream getInput() {
        return input;
    }

    public Socket getSocket() {
        return socket;
    }

    public void setOutput(Socket s) {
        try {
            output = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    public void setInput(Socket s) {
        try {
            input =  new DataInputStream(new BufferedInputStream(s.getInputStream()));
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
        generateKeyPair();
        tradeKeys();
        Log.d("CLIENT", "Connection Established!\n");
    }

    //Generate Asymmetric Key pair
    private void generateKeyPair() {
        Log.d("CLIENT", "Generating Key Pair");
        try {
            KeyPairGenerator keyPairGenerator = null;
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            cipher = Cipher.getInstance("RSA");
            cli_pubkey = keyPair.getPublic();
            cli_privkey = keyPair.getPrivate();
            Log.d("CLIENT", "Key Pair Generation: SUCCESS");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            Log.d("CLIENT", "Key Pair Generation: FAIL");
        }
    }

    private void tradeKeys() {
        //Send public key to server
        try {
            File client_pubkeyfile = new File("pubkey");
            FileInputStream fis = new FileInputStream("pubkey");
            byte[] client_encodedpubkey = new byte [(int) client_pubkeyfile.length()];
            fis.read(client_encodedpubkey);
            fis.close();
            output.write(client_encodedpubkey);
            output.flush();
        } catch (IOException e) {
            Log.d("CLIENT", "Client Public Key wasn't delivered");
        }

        //Receive public key from server
        try {
            byte[] aux = new byte[16 * 1024];
            FileOutputStream fos = new FileOutputStream("server_pubkey");

            int count;
            while((count = input.read(aux)) > 0) {
                fos.write(aux, 0, count);
            }
            fos.close();
        } catch (IOException e) {
            Log.d("CLIENT", "Server Public Key wasn't received");
        }

        //Load Server Public key
        try {
            File filePublicKey = new File("server_pubkey");
            FileInputStream fis = new FileInputStream("server_pubkey");
            byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
            fis.read(encodedPublicKey);
            fis.close();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                    encodedPublicKey);
            server_pubkey = keyFactory.generatePublic(publicKeySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d("CLIENT", "Server Public Key wasn't loaded");
        }
    }

    private String hashPasswordSHA512 (String password, String salt) {
        String hashedPass = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt.getBytes("UTF-8"));
            byte[] bytes = md.digest(password.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for(int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            hashedPass = sb.toString();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            Log.d("CLIENT", "Password wasn't hashed");
        }
        return hashedPass;
    }

    public void login(String email, String password) throws ConnectionFailedException,
            IncorrectPasswordException, AccountDoesntExistException {
        String msg;

        Log.d("CLIENT", "Logging in with " + email + " " + password);
        sendMsg("APP" + delim + "LOGIN" + delim + email + delim + password);
        /*output.writeBytes("APP" + delim + "LOGIN" + delim + email + delim + password + '\n');
        msg = input.readLine();*/
        msg = rcvMsg();

        if(msg.isEmpty()) {
            //the message being empty, means that there was an error in the encryption
            //THROW NEW EXCEPTION? ex. CipherErrorException
            return;
        }

        if (msg.equals("OK")) {
            Log.d("CLIENT", "Log In: SUCCESS");
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
            String hashedPass = hashPasswordSHA512(pass, id);
            output.writeBytes("ADD" + delim + id + delim + hashedPass + '\n');
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

    private void sendMsg(String msg) throws ConnectionFailedException {
        //TODO: Add counter, signature, SALT(?), etc...
        try {
            byte[] send_msg = encrypt(msg);
            output.writeInt(send_msg.length);
            output.write(send_msg);
            Log.d("CLIENT", "Send Message: SUCCESS");
        } catch (IOException | CipherErrorException e) {
            Log.d("CLIENT", "Send Message: FAIL");
            throw new ConnectionFailedException();
        }
    }

    private String rcvMsg() throws ConnectionFailedException {
        String msg = "";
        //TODO: confirm counter, signature and isolate the message
        try {
            byte[] rcvd_msg = new byte[input.readInt()];
            input.readFully(rcvd_msg);
            msg = decrypt(rcvd_msg);
            Log.d("CLIENT", "Receive Message: SUCCESS");
        } catch (IOException | CipherErrorException e) {
            Log.d("CLIENT", "Receive Message: FAIL");
            throw new ConnectionFailedException();
        }
        return msg;
    }

    private byte[] encrypt(String msg) throws CipherErrorException {
        byte[] result = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, server_pubkey);
            result = cipher.doFinal(msg.getBytes("UTF-8"));
            Log.d("CLIENT", "Encrypted message: " + new String(result, "UTF-8"));
        } catch (InvalidKeyException | UnsupportedEncodingException | IllegalBlockSizeException
                | BadPaddingException e) {
            Log.d("CLIENT", "Encryption: FAILED");
            throw new CipherErrorException();
        }
        return result;
    }

    private String decrypt(byte[] msg) throws CipherErrorException {
        String result = "";
        try {
            cipher.init(Cipher.DECRYPT_MODE, cli_privkey);
            byte[] aux = cipher.doFinal(msg);
            result = new String(aux, "UTF-8");
            Log.d("CLIENT", "Decrypted message: " + result);
        } catch (InvalidKeyException | UnsupportedEncodingException | IllegalBlockSizeException
                | BadPaddingException e) {
            Log.d("CLIENT", "Decryption: FAILED");
            throw new CipherErrorException();
        }
        return result;
    }
}

