package client;

import general.Packet;
import general.Security;
import libs.FileManagement;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.util.*;

public class Client {
    private String name;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Server server;
    private List<ClientHandler> clientHandlerList;
    private DataInputStream dis;
    private DataOutputStream dos;
    private byte[] defaultPhysicalKey;
    private Queue<byte[]> sendPacketsQueue;

//    private HashMap<String, Overflow> receiveOverflows;
//    private HashMap<String, Overflow> sendOverflows;
    private HashMap<String, Overflow> overflows;


    public Client() throws IOException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter your name (less than 16 characters) : ");
        name = scanner.next();
        KeyPair keyPair = general.Security.RSA.keyPairGenerator();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        String text = FileManagement.readFile("filename.txt");
        String[] serverConfigs = text.split(" ");
        server = new Server(serverConfigs[0], Integer.parseInt(serverConfigs[1]), serverConfigs[2]);
        clientHandlerList = new ArrayList<>();
        sendPacketsQueue = new LinkedList<>();
//        receiveOverflows = new HashMap<>();
//        sendOverflows = new HashMap<>();
        overflows = new HashMap<>();

        InetAddress inetAddress = InetAddress.getByName("localhost");
        Socket socket = new Socket(inetAddress, server.port);

        System.out.println("server is up ...");
        dis = new DataInputStream(socket.getInputStream());
        dos = new DataOutputStream(socket.getOutputStream());

        // initialization phase
        byte[] received = new byte[Packet.PACKET_SIZE];
        FileManagement.makeDirectory(name);
        Packet initializationPacket = Packet.build.clientInitialize(name, publicKey, server.publicKey);
        System.out.println("client public key : " + Security.RSA.getPublicKeyStr(publicKey));
        byte[] initializationPacketBytes = Packet.helper.getNormalPacketBytes(initializationPacket);
        dos.write(initializationPacketBytes);
        dis.read(received, 0, received.length);
        if (received.length == Packet.PACKET_SIZE) {
            Packet initializeAckPacket = Packet.helper.getNormalPacket(received);
            if (initializeAckPacket.getAckNum() == 1) {
                System.out.println("client handler is created successfully in server");
            }
        }
        dis.read(received, 0, received.length);
        if (received.length == Packet.PACKET_SIZE) {
            Packet physicalKeyPacket = Packet.helper.getNormalPacket(received);
            defaultPhysicalKey = general.Security.RSA.decrypt(privateKey, physicalKeyPacket.getData());
            Packet physicalKeyAckPacket = Packet.build.acknowledgement(name, "server", physicalKeyPacket.getAckNum());
            byte[] physicalKeyAckBytes = Packet.helper.getNormalPacketBytes(physicalKeyAckPacket);
            System.out.println("default physical key is " + new String(defaultPhysicalKey));
            dos.write(physicalKeyAckBytes);
        }

        System.out.println("************************************************************************************\n");


        Thread sendPacketsThread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    if (sendPacketsQueue.peek() != null) {
                        try {
                            byte[] bytes = sendPacketsQueue.remove();
                            dos.write(bytes);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        });

        Thread readPacketsThread = new Thread(new Runnable() {
            @Override
            public void run() {

                while (true) {
                    byte[] receive = new byte[Packet.FILE_PACKET_SIZE];
                    try {
                        dis.read(receive, 0, receive.length);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    Packet packet = null;
                    if (Arrays.equals(new byte[Packet.FILE_PACKET_SIZE - Packet.PACKET_SIZE],
                            Arrays.copyOfRange(receive, Packet.PACKET_SIZE, Packet.FILE_PACKET_SIZE)))
                        packet = Packet.helper.getNormalPacket(Arrays.copyOfRange(receive, 0, Packet.PACKET_SIZE));
                    else
                        packet = Packet.helper.getFilePacket(receive);
//                    System.out.println("new packet received");
                    boolean isNewClientHandler = true;
                    for (ClientHandler clientHandler : clientHandlerList) {
                        if (clientHandler.getClientName().equals(packet.getSourceName())) {
                            if (overflows.getOrDefault(clientHandler.getClientName(), null) == null) {
                                overflows.put(clientHandler.getClientName(), Overflow.build.receiver(Client.this, clientHandler));
                                overflows.get(clientHandler.getClientName()).addPacket(packet);
                                overflows.get(clientHandler.getClientName()).start();
                            }
                            else {
                                if (overflows.get(clientHandler.getClientName()).getStatus() == Overflow.STATUS.RUNNING) {
                                    overflows.get(clientHandler.getClientName()).addPacket(packet);
                                } else {
                                    overflows.put(clientHandler.getClientName(), Overflow.build.receiver(Client.this, clientHandler));
                                    overflows.get(clientHandler.getClientName()).addPacket(packet);
                                    overflows.get(clientHandler.getClientName()).start();
                                }
                            }
                            isNewClientHandler = false;
                        }
                    }
                    if (isNewClientHandler) {
//                        System.out.println("new client");
                        ClientHandler newClientHandler = new ClientHandler(packet.getSourceName(), defaultPhysicalKey);
                        clientHandlerList.add(newClientHandler);
//                        System.out.println("new client handler created!");
                        overflows.put(newClientHandler.getClientName(), Overflow.build.receiver(Client.this, newClientHandler));
                        overflows.get(newClientHandler.getClientName()).addPacket(packet);
                        overflows.get(newClientHandler.getClientName()).start();
                    }
                }
            }
        });

        Thread readCommandLineThread = new Thread(new Runnable() {
            @Override
            public void run() {
                Scanner scanner = new Scanner(System.in);
                while (true) {
                    String commandLine = scanner.nextLine();
                    switch (CommandLine.commandType(commandLine)) {
                        case CommandLine.TYPE.MESSAGE_COMMAND: {
//                            System.out.println("command recognizes as message");
                            String[] commandParts = CommandLine.getCommandParts(commandLine);
                            boolean isClientHandlerExist = false;
                            for (ClientHandler clientHandler : clientHandlerList) {
                                if (clientHandler.getClientName().equals(commandParts[0])) {
                                    isClientHandlerExist = true;
                                    if (overflows.getOrDefault(clientHandler.getClientName(), null) != null) {
                                        if (overflows.get(clientHandler.getClientName()).getStatus() == Overflow.STATUS.RUNNING)
                                            System.out.println("Some packets are sending/receiving from current user.");
                                        else {
                                            overflows.put(clientHandler.getClientName(), Overflow.build.sender(Client.this, clientHandler, commandParts[1]));
                                            overflows.get(clientHandler.getClientName()).start();
                                        }
                                    } else {
                                        overflows.put(clientHandler.getClientName(), Overflow.build.sender(Client.this, clientHandler, commandParts[1]));
                                        overflows.get(clientHandler.getClientName()).start();
                                    }
                                }
                            }
                            if (!isClientHandlerExist) {
//                                System.out.println("client handler is not exists");
                                ClientHandler clientHandler = new ClientHandler(commandParts[0], defaultPhysicalKey);
                                clientHandlerList.add(clientHandler);
                                overflows.put(clientHandler.getClientName(), Overflow.build.sender(Client.this, clientHandler, commandParts[1]));
//                                System.out.println("send overflow created");
                                overflows.get(clientHandler.getClientName()).start();
                            }
                            break;
                        }
                        case CommandLine.TYPE.FILE_COMMAND: {
//                            System.out.println("command recognizes as file command");
                            String[] commandParts = CommandLine.getCommandParts(commandLine);
                            boolean isFileExists = false;
                            File file = null;
                            for (File item : FileManagement.getDirectoryFiles(name)) {
                                if (item.getName().equals(commandParts[1])) {
                                    isFileExists = true;
                                    file = item;
                                    break;
                                }
                            }
                            if (!isFileExists) {
//                                System.out.println("File not found!!!");
                                break;
                            }
                            boolean isClientHandlerExist = false;
                            for (ClientHandler clientHandler : clientHandlerList) {
                                if (clientHandler.getClientName().equals(commandParts[0])) {
                                    isClientHandlerExist = true;
                                    if (overflows.getOrDefault(clientHandler.getClientName(), null) != null) {
                                        if (overflows.get(clientHandler.getClientName()).getStatus() == Overflow.STATUS.RUNNING)
                                            System.out.println("Some packets are sending/receiving from current user.");
                                        else {
                                            overflows.put(clientHandler.getClientName(), Overflow.build.fileSender(Client.this, clientHandler, file));
                                            overflows.get(clientHandler.getClientName()).start();
                                        }
                                    } else {
                                        overflows.put(clientHandler.getClientName(), Overflow.build.fileSender(Client.this, clientHandler, file));
                                        overflows.get(clientHandler.getClientName()).start();
                                    }
                                }
                            }
                            if (!isClientHandlerExist) {
//                                System.out.println("client handler is not exists");
                                ClientHandler clientHandler = new ClientHandler(commandParts[0], defaultPhysicalKey);
                                clientHandlerList.add(clientHandler);
                                overflows.put(clientHandler.getClientName(), Overflow.build.fileSender(Client.this, clientHandler, file));
//                                System.out.println("send overflow created");
                                overflows.get(clientHandler.getClientName()).start();
                            }
                            break;
                        }
                        case CommandLine.TYPE.UNDEFINE_COMMAND:
                            System.out.println("wrong command!!!");
                            break;
                    }
                }
            }
        });

        readCommandLineThread.start();
        sendPacketsThread.start();
        readPacketsThread.start();
//        System.out.println("all threads are running!!!!!");
    }




    class Server {
        private String ip;
        private int port;
        private PublicKey publicKey;

        public Server(String ip, int port, String publicKey) {
            this.ip = ip;
            this.port = port;
            this.publicKey = general.Security.RSA.getPublicKeyFromStr(publicKey);
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public int getPort() {
            return port;
        }

        public String getIp() {
            return ip;
        }

    }

    public String getName() {
        return name;
    }

    public Server getServer() {
        return server;
    }

    public void addToSendPacketQueue(byte[] packet) {
        sendPacketsQueue.add(packet);
    }

    public List<ClientHandler> getClientHandlerList() {
        return clientHandlerList;
    }

    public void addClientHandler(ClientHandler clientHandler) {
        clientHandlerList.add(clientHandler);
    }

    public byte[] getDefaultPhysicalKey() {
        return defaultPhysicalKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
