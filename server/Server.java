package server;

import general.Security;
import libs.FileManagement;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

public class Server {
    private String ip;
    private int port;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private List<ClientHandler> clients;
    private byte[] defaultPhysicalKey;

    public Server() throws IOException, NoSuchAlgorithmException {
        InetAddress inetAddress = InetAddress.getLocalHost();
        ip = inetAddress.getHostAddress();
        Random random = new Random();
        port = random.nextInt(12345);
        KeyPair keyPair = Security.RSA.keyPairGenerator();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        String serverConfig = ip + " " + port + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded());
        FileManagement.writeFile("filename.txt", serverConfig);
        clients = new ArrayList<>();
        defaultPhysicalKey = new byte[32];
        new Random().nextBytes(defaultPhysicalKey);
//        System.out.println("default physical is " + new String(defaultPhysicalKey));

        ServerSocket serverSocket = new ServerSocket(port);
        Socket socket;
        while (true) {
            socket = serverSocket.accept();
//            System.out.println("New client request received. It is : " + socket);
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

//            System.out.println("Creating a new handler for this client ...");
            ClientHandler clientHandler = new ClientHandler(socket, dis, dos, this);
            Thread t = new Thread(clientHandler);
//            System.out.println("Adding client to active clients list");
            clients.add(clientHandler);
            t.start();
        }
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public List<ClientHandler> getClients() {
        return clients;
    }

    public void setClients(List<ClientHandler> clients) {
        this.clients = clients;
    }

    public byte[] getDefaultPhysicalKey() {
        return defaultPhysicalKey;
    }

    public void setDefaultPhysicalKey(byte[] defaultPhysicalKey) {
        this.defaultPhysicalKey = defaultPhysicalKey;
    }
}
