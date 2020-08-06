package server;



import general.Packet;
import general.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

public class ClientHandler implements Runnable{
    private Server server;
    private Socket socket;
    private String name;
    private PublicKey publicKey;
    private final DataInputStream dis;
    private final DataOutputStream dos;

    public ClientHandler(Socket socket, DataInputStream dis, DataOutputStream dos, Server server) {
        this.socket = socket;
        this.dis = dis;
        this.dos = dos;
        this.server = server;
    }

    @Override
    public void run() {
        byte[] receive = new byte[Packet.PACKET_SIZE];
        try {

            dis.read(receive, 0, receive.length);
            if (receive.length == Packet.PACKET_SIZE) {
                Packet initializePacket = Packet.helper.getNormalPacket(receive);
                if (initializePacket.getType() == Packet.TYPE.CLIENT_INITIALIZE) {
//                    System.out.println("get a new initialize packet");
                    byte[] data = Security.RSA.decrypt(server.getPrivateKey(), initializePacket.getData());
                    int i = 0;
                    for (i = 0; i < data.length; i++) {
                        if (data[i] == 0)
                            break;
                    }
                    this.name = new String( Arrays.copyOfRange(data, 0, i));
                    this.publicKey = Security.RSA.getPublicKeyFromBytes(Arrays.copyOfRange(data, i + 1, data.length));
//                    System.out.println("client name is : " + new String(Arrays.copyOfRange(data, 0, i)));
//                    System.out.println("client public key is " + Security.RSA.getPublicKeyStr(publicKey));
                    Packet initializeAckPacket = Packet.build.acknowledgement("server", name, initializePacket.getAckNum());
                    byte[] initializeAckBytes = Packet.helper.getNormalPacketBytes(initializeAckPacket);
                    dos.write(initializeAckBytes);

                    Packet setDefaultPhysicalKeyPacket = Packet.build.setDefaultPhysicalKey(name, server.getDefaultPhysicalKey(), publicKey);
                    byte[] setDefaultPhysicalKeyBytes = Packet.helper.getNormalPacketBytes(setDefaultPhysicalKeyPacket);
                    dos.write(setDefaultPhysicalKeyBytes);
                    dis.read(receive, 0, receive.length);
                    if (receive.length == Packet.PACKET_SIZE) {
                        Packet setPhysicalKeyAckPacket = Packet.helper.getNormalPacket(receive);
//                        if (setPhysicalKeyAckPacket.getAckNum().equals(setDefaultPhysicalKeyPacket.getAckNum())) {
//                            dis.read(receive, 0, receive.length);
//                        }
                    }
//                    System.out.println("****************************************************************************************************\n");
                }
            }
            while (true) {
                byte[] rec = new byte[Packet.FILE_PACKET_SIZE];
//                System.out.println("server is ready to receive data");
                dis.read(rec, 0, rec.length);
//                System.out.println("server receives data");
                Packet packet = null;
                if (Arrays.equals(new byte[Packet.FILE_PACKET_SIZE - Packet.PACKET_SIZE],
                        Arrays.copyOfRange(rec, Packet.PACKET_SIZE, Packet.FILE_PACKET_SIZE)))
                    packet = Packet.helper.getNormalPacket(Arrays.copyOfRange(rec, 0, Packet.PACKET_SIZE));
                else
                    packet = Packet.helper.getFilePacket(rec);
                for (ClientHandler receiverClient : server.getClients()) {
                    if (receiverClient.name.equals(packet.getDestName())) {
                        if (packet.getType() == Packet.TYPE.SESSION_KEY) {
//                            System.out.println("session packet from " + packet.getSourceName() + " to " + packet.getDestName() + "\n");
                            byte[] data = Security.RSA.decrypt(server.getPrivateKey(), Arrays.copyOfRange(packet.getData(), 0, packet.getDataOffset()));
                            data = Security.RSA.encrypt(receiverClient.publicKey, data);
                            packet.setData(data);
                            packet.setDataOffset(data.length);
                            byte[] packetBytes = Packet.helper.getNormalPacketBytes(packet);
                            receiverClient.dos.write(packetBytes);
                        } else {
                            byte[] packetBytes = null;
                            if (packet.getType() == Packet.TYPE.FILE)
                                packetBytes = Packet.helper.getFilePacketBytes(packet);
                            else
                                packetBytes = Packet.helper.getNormalPacketBytes(packet);
                            receiverClient.dos.write(packetBytes);
                        }
                    }
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        try {
            dis.close();
            dos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
