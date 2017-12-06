package ist.meic.sirs.securechildlocator;

import android.content.Context;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
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
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import ist.meic.sirs.securechildlocator.exceptions.*;

import static android.os.Environment.DIRECTORY_DOCUMENTS;

/**
 * Created by pedro on 11/11/2017.
 */

public class Client {

    private static Client instance = null;

    private PrivateKey cli_privkey;
    private PublicKey cli_pubkey;
    private PublicKey server_pubkey;
    private SecretKey sk;
    private byte[] iv;
    private Cipher cipher;

    private static String server_ip;
    private static int server_port;
    private DataInputStream input;
    private DataOutputStream output;
    private Socket socket;

    private Context fileContext;

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

    public void setContext(Context context) {
        fileContext = context;
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
            //socket.setSoTimeout(1000);
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
        rcvSessionKey();
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

            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(cli_pubkey.getEncoded());
            //FileOutputStream fos = new FileOutputStream(DIRECTORY_DOCUMENTS + "pubkey");
            FileOutputStream fos = fileContext.openFileOutput("pubkey", Context.MODE_PRIVATE);
            fos.write(x509EncodedKeySpec.getEncoded());
            fos.close();

            Log.d("CLIENT", "Key Pair Generation: SUCCESS");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException e) {
            Log.d("CLIENT", "Key Pair Generation: FAIL");
        }
    }

    private void tradeKeys() {
        //Send public key to server
        try {
            File client_pubkeyfile = new File(fileContext.getFilesDir(), "pubkey");
            FileInputStream fis = fileContext.openFileInput("pubkey");
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
            FileOutputStream fos = fileContext.openFileOutput("server_pubkey", Context.MODE_PRIVATE);

            int count;
            //try {
                //while ((count = input.read(aux)) > 0) {
                    count = input.read(aux);
                    fos.write(aux, 0, count);
                //}
            //} catch (SocketTimeoutException e) {

            //}
            fos.close();
        } catch (IOException e) {
            Log.d("CLIENT", "Server Public Key wasn't received");
        }

        //Load Server Public key
        try {
            File filePublicKey = new File(fileContext.getFilesDir(), "server_pubkey");
            FileInputStream fis = fileContext.openFileInput("server_pubkey");
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

    private void rcvSessionKey() {

        try {
            int ivSize = 16;
            byte[] msg = new byte[input.readInt()];
            input.readFully(msg);

            iv = new byte[ivSize];
            System.arraycopy(msg, 0, iv, 0, ivSize);

            byte[] encrypted = new byte[msg.length - ivSize];
            System.arraycopy(msg, ivSize, encrypted, 0, encrypted.length);
            sk = new SecretKeySpec(decrypt(encrypted, "RSA"), "AES");

            sendMsg("OK".getBytes("UTF-8"),  "AES");

        } catch (IOException | ConnectionFailedException e) {

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
            IncorrectPasswordException, AccountDoesntExistException, UnsupportedEncodingException {
        String msg;
        byte[] rcvd;

        Log.d("CLIENT", "Logging in with " + email + " " + password);
        sendMsg(("APP" + delim + "LOGIN" + delim + email + delim + password).getBytes("UTF-8"), "AES");
        /*output.writeBytes("APP" + delim + "LOGIN" + delim + email + delim + password + '\n');
        msg = input.readLine();*/
        rcvd = rcvMsg("AES");

        msg = new String(rcvd, "UTF-8");

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

    private void sendMsg(byte[] msg, String type) throws ConnectionFailedException {
        //TODO: Add counter, signature, SALT(?), etc...
        try {
            byte[] send_msg = encrypt(msg, type);
            output.writeInt(send_msg.length);
            output.write(send_msg);
            Log.d("CLIENT", "Send Message: SUCCESS");
        } catch (IOException | CipherErrorException e) {
            Log.d("CLIENT", "Send Message: FAIL");
            throw new ConnectionFailedException();
        }
    }

    private byte[] rcvMsg(String type) throws ConnectionFailedException {
        byte[] msg = null;
        //TODO: confirm counter, signature and isolate the message
        try {
            byte[] rcvd_msg = new byte[input.readInt()];
            input.readFully(rcvd_msg);
            msg = decrypt(rcvd_msg, type);
            Log.d("CLIENT", "Receive Message: SUCCESS");
        } catch (IOException e) {
            Log.d("CLIENT", "Receive Message: FAIL");
            throw new ConnectionFailedException();
        }
        return msg;
    }

    private byte[] encrypt(byte[] msg, String type) throws CipherErrorException {
        byte[] result = null;

        switch(type) {
            case "RSA":
                try {
                    cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, server_pubkey);
                    result = cipher.doFinal(msg);
                    Log.d("CLIENT", "Encrypted message: " + new String(result, "UTF-8"));
                } catch (InvalidKeyException | UnsupportedEncodingException | IllegalBlockSizeException
                        | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                    Log.d("CLIENT", "Encryption: FAILED");
                    throw new CipherErrorException();
                }
            case "AES":
                try {
                    cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, server_pubkey);
                    result = cipher.doFinal(msg);
                    Log.d("CLIENT", "Encrypted message: " + new String(result, "UTF-8"));
                } catch (InvalidKeyException | UnsupportedEncodingException | IllegalBlockSizeException
                        | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                    Log.d("CLIENT", "Encryption: FAILED");
                    throw new CipherErrorException();
                }
        }

        return result;
    }

    private byte[] decrypt(byte[] msg, String type) {
        byte[] result = null;

        switch(type) {
            case"RSA":
                try {
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.DECRYPT_MODE, cli_privkey);
                    result = cipher.doFinal(msg);
                } catch (InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException | NoSuchAlgorithmException
                        | NoSuchPaddingException e) {
                    System.out.println("Decryption: FAILED");
                    e.printStackTrace();
                }
                break;

            case"AES":
                try {
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));
                    result = cipher.doFinal(msg);

                    //generateIV for next communication
                    generateIV(msg);

                } catch (InvalidKeyException | InvalidAlgorithmParameterException
                        | NoSuchAlgorithmException | NoSuchPaddingException
                        | IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }
                break;
        }

        return result;
    }

    private void generateIV(byte[] msg) {
        iv = Arrays.copyOfRange(msg, 0, 16);
    }
}

