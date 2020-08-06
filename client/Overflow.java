package client;

import general.Packet;
import general.Security;
import libs.FileManagement;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Overflow extends Thread {
    private Client client;
    private int type;
    private int status;
    private Queue<Packet> receivePackets;

    private ClientHandler receiver;
    private String text;
    private File file;

    private ClientHandler sender;

    private static final int TIME_OUT = 1500000;
    @Override
    public void run() {
        switch (type) {
            case TYPE.MESSAGE_SENDER_OVERFLOW:
                senderOverFlow();
                break;
            case TYPE.MESSAGE_RECEIVER_OVERFLOW:
                receiverOverFlow();
                break;
            case TYPE.FILE_SENDER_OVERFLOW:
                fileSenderOverflow();
                break;
        }
    }

    private void senderOverFlow() {
        status = STATUS.RUNNING;
        long time;
        byte[] sessionKey = new byte[16];
        new Random().nextBytes(sessionKey);
        try {
            Packet sessionKeyPacket = Packet.build.sessionKey(client.getName(), receiver.getClientName(), sessionKey, receiver.getPhysicalKey(), client.getServer().getPublicKey());
            byte[] sessionKeyBytes = Packet.helper.getNormalPacketBytes(sessionKeyPacket);
            client.addToSendPacketQueue(sessionKeyBytes);
//            System.out.println("overflow - breakpoint 1");
            Packet acknowledgePacket = Overflow.helper.getPacket(this);
            if (acknowledgePacket == null)
                return;
            receiver.setSessionKey(sessionKey);
//            System.out.println("session key sets successfully !!!");
            Packet messageConfigPacket = Packet.build.messageConfiguration(client.getName(), receiver.getClientName(), receiver.getSessionKey(), text.length());
            byte[] messageConfigPacketBytes = Packet.helper.getNormalPacketBytes(messageConfigPacket);
            client.addToSendPacketQueue(messageConfigPacketBytes);
            acknowledgePacket = Overflow.helper.getPacket(this);
            if (acknowledgePacket == null)
                return;
//            System.out.println("ready to send data!!!!");
            Integer packetCounts = Packet.helper.countMessagePackets(text.length());
            for (int i = 0; i < packetCounts; i++) {
                byte[] data = null;
                if (i != packetCounts - 1) {
                    data = Arrays.copyOfRange(text.getBytes(), (i * 1024), ((i + 1) * 1024));
                } else {
                    data = Arrays.copyOfRange(text.getBytes(), i * 1024, text.getBytes().length);
                }
                Packet messagePacket = Packet.build.message(client.getName(), receiver.getClientName(), receiver.getSessionKey(), data, i);
                byte[] messagePacketBytes = Packet.helper.getNormalPacketBytes(messagePacket);
                client.addToSendPacketQueue(messagePacketBytes);
                acknowledgePacket = Overflow.helper.getPacket(this);
                if (acknowledgePacket == null)
                    return;
                if (acknowledgePacket.getAckNum() == i) {
                    continue;
                } else {
                    sessionKey = new byte[16];
                    new Random().nextBytes(sessionKey);
                    sessionKeyPacket = Packet.build.sessionKey(client.getName(), receiver.getClientName(), sessionKey, receiver.getPhysicalKey(), client.getServer().getPublicKey());
                    sessionKeyBytes = Packet.helper.getNormalPacketBytes(sessionKeyPacket);
                    client.addToSendPacketQueue(sessionKeyBytes);
                    acknowledgePacket = Overflow.helper.getPacket(this);
                    if (acknowledgePacket == null)
                        return;
                    receiver.setSessionKey(sessionKey);
//                    System.out.println("session key has set again!!!!");
                    i -= 1;
                }
            }
//            System.out.println("message sent completely!!!!");
            byte[] physicalKey = new byte[32];
            new Random().nextBytes(physicalKey);
            Packet physicalKeyPacket = Packet.build.message(client.getName(), receiver.getClientName(), sessionKey, physicalKey, 0);
            byte[] physicalKeyPacketBytes = Packet.helper.getNormalPacketBytes(physicalKeyPacket);
            client.addToSendPacketQueue(physicalKeyPacketBytes);
            acknowledgePacket = Overflow.helper.getPacket(this);
            if (acknowledgePacket == null)
                return;
            receiver.setPhysicalKey(physicalKey);
//            System.out.println("session finished!!!");
            status = STATUS.FINISH;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void receiverOverFlow() {
        try {

            status = STATUS.RUNNING;
            long time;
            Packet sessionKeyPacket = Overflow.helper.getPacket(this);
            if (sessionKeyPacket == null)
                return;
            boolean isNewClientHandler = true;
            ClientHandler senderClientHandler = null;
            for (ClientHandler clientHandler : client.getClientHandlerList()) {
                if (sessionKeyPacket.getSourceName().equals(clientHandler.getClientName())) {
                    senderClientHandler = clientHandler;
                    isNewClientHandler = false;
                }
            }
            if (isNewClientHandler) {
                ClientHandler clientHandler = new ClientHandler(sessionKeyPacket.getSourceName(), client.getDefaultPhysicalKey());
                senderClientHandler = clientHandler;
            }
            byte[] sessionKey = Security.RSA.decrypt(client.getPrivateKey(), sessionKeyPacket.getData());
            Security.AesCtr aesCtr = new Security.AesCtr(senderClientHandler.getPhysicalKey());
            sessionKey = aesCtr.decrypt(sessionKey);
            senderClientHandler.setSessionKey(sessionKey);


            Packet acknowledgePacket = Packet.build.acknowledgement(client.getName(), senderClientHandler.getClientName(), sessionKeyPacket.getAckNum());
            byte[] acknowledgeBytes = Packet.helper.getNormalPacketBytes(acknowledgePacket);
            client.addToSendPacketQueue(acknowledgeBytes);
//            System.out.println("Session key sets successfully !!!!!");

            Packet configPacket = Overflow.helper.getPacket(this);
            if (configPacket == null)
                return;

            Security.AesCtr sessionAesCtr = new Security.AesCtr(senderClientHandler.getSessionKey());
            if (!Packet.helper.checkMAC(configPacket, senderClientHandler.getSessionKey())) {
                System.out.println("MAC ERROR!");
                return;
            }
            acknowledgePacket = Packet.build.acknowledgement(client.getName(), senderClientHandler.getClientName(), configPacket.getAckNum());
            acknowledgeBytes = Packet.helper.getNormalPacketBytes(acknowledgePacket);
            client.addToSendPacketQueue(acknowledgeBytes);
            senderClientHandler.setDefaultSessionExpiration();
//            System.out.println("ready to get data!!!!");
            if (configPacket.getType() == Packet.TYPE.MESSAGE_CONFIGURATION) {
                StringBuilder message = new StringBuilder();
                Integer packetCounts = Integer.parseInt(new String(sessionAesCtr.decrypt(configPacket.getData())));
                for (int i = 0; i < packetCounts; i++) {
                    Packet data = Overflow.helper.getPacket(this);
                    if (data == null)
                        return;

                    if (senderClientHandler.getSessionKeyExpiration() < System.currentTimeMillis()) {
                        // session key has expired
                        acknowledgePacket = Packet.build.acknowledgement(client.getName(), senderClientHandler.getClientName(), -1);
                        acknowledgeBytes = Packet.helper.getNormalPacketBytes(acknowledgePacket);
                        client.addToSendPacketQueue(acknowledgeBytes);
                        time = System.currentTimeMillis();
                        sessionKeyPacket = Overflow.helper.getPacket(this);
                        if (sessionKeyPacket == null)
                            return;

                        sessionKey = Security.RSA.decrypt(client.getPrivateKey(), sessionKeyPacket.getData());
                        aesCtr = new Security.AesCtr(senderClientHandler.getPhysicalKey());
                        sessionKey = aesCtr.decrypt(sessionKey);
                        senderClientHandler.setSessionKey(sessionKey);
                        senderClientHandler.setDefaultSessionExpiration();
                        acknowledgePacket = Packet.build.acknowledgement(client.getName(), senderClientHandler.getClientName(), sessionKeyPacket.getAckNum());
                        acknowledgeBytes = Packet.helper.getNormalPacketBytes(acknowledgePacket);
                        client.addToSendPacketQueue(acknowledgeBytes);
                        System.out.println("session key has set again!!!!");
                        i -= 1;
                    } else {
                        // session key is ok
                        if (Packet.helper.checkMAC(data, sessionKey)) {
                            message.append(new String(Packet.helper.getPacketData(data, sessionKey)));
                            acknowledgePacket = Packet.build.acknowledgement(client.getName(), senderClientHandler.getClientName(), data.getSeqNum());
                            acknowledgeBytes = Packet.helper.getNormalPacketBytes(acknowledgePacket);
                            client.addToSendPacketQueue(acknowledgeBytes);
//                            System.out.println("MAC is OK");
                        } else {
                            System.out.println("MAC is wrong");
                        }
                    }
                }
//                System.out.println("message received completely!!!!");
                System.out.println(senderClientHandler.getClientName() + " : " + message);
            }

            if (configPacket.getType() == Packet.TYPE.FILE_CONFIGURATION) {
                List<byte[]> fileList = new ArrayList<>();
                String[] fileConfig = Packet.helper.decodeFilePacketConfig(new String(sessionAesCtr.decrypt(configPacket.getData())));
                int packetCounts = Integer.parseInt(fileConfig[0]);
                String outputFilePath = client.getName() + "/" + fileConfig[1];
                File outputFile = new File(outputFilePath);
                for (int i = 0; i < packetCounts; i++) {
                    Packet data = Overflow.helper.getPacket(this);
                    if (data == null)
                        return;
//                    System.out.println("hello");

                    if (senderClientHandler.getSessionKeyExpiration() < System.currentTimeMillis()) {
                        // session key has expired
                        acknowledgePacket = Packet.build.acknowledgement(client.getName(), senderClientHandler.getClientName(), -1);
                        acknowledgeBytes = Packet.helper.getNormalPacketBytes(acknowledgePacket);
                        client.addToSendPacketQueue(acknowledgeBytes);
                        time = System.currentTimeMillis();
                        sessionKeyPacket = Overflow.helper.getPacket(this);
                        if (sessionKeyPacket == null)
                            return;

                        sessionKey = Security.RSA.decrypt(client.getPrivateKey(), sessionKeyPacket.getData());
                        aesCtr = new Security.AesCtr(senderClientHandler.getPhysicalKey());
                        sessionKey = aesCtr.decrypt(sessionKey);
                        senderClientHandler.setSessionKey(sessionKey);
                        senderClientHandler.setDefaultSessionExpiration();
                        acknowledgePacket = Packet.build.acknowledgement(client.getName(), senderClientHandler.getClientName(), sessionKeyPacket.getAckNum());
                        acknowledgeBytes = Packet.helper.getNormalPacketBytes(acknowledgePacket);
                        client.addToSendPacketQueue(acknowledgeBytes);
                        System.out.println("session key has set again!!!!");
                        i -= 1;
                    } else {
                        // session key is ok
                        if (Packet.helper.checkMAC(data, sessionKey)) {
                            fileList.add(Packet.helper.getPacketData(data, sessionKey));
                            acknowledgePacket = Packet.build.acknowledgement(client.getName(), senderClientHandler.getClientName(), data.getSeqNum());
                            acknowledgeBytes = Packet.helper.getNormalPacketBytes(acknowledgePacket);
                            client.addToSendPacketQueue(acknowledgeBytes);
//                            System.out.println("MAC is OK");
                        } else {
                            System.out.println("MAC is wrong");
                        }
                    }


                }
                int temp = 0;
                for (int j = 0; j < fileList.size(); j++) {
                    temp += fileList.get(j).length;
                }
                byte[] data = new byte[temp];
                for (int i = 0; i < fileList.size(); i++) {
                    System.arraycopy(fileList.get(i), 0, data, i * fileList.get(0).length, fileList.get(i).length);
                }
                FileManagement.writeToFile(data, outputFile);
                System.out.println(senderClientHandler.getClientName() + " (FILE) " + " : " + outputFile.getName());
            }

//            System.out.println("Physical key is going to create...");
            Packet physicalKeyPacket = Overflow.helper.getPacket(this);
            if (physicalKeyPacket == null)
                return;
            if (Packet.helper.checkMAC(physicalKeyPacket, sessionKey)) {
                byte[] physicalKey = Packet.helper.getPacketData(physicalKeyPacket, sessionKey);
                acknowledgePacket = Packet.build.acknowledgement(client.getName(), senderClientHandler.getClientName(), physicalKeyPacket.getSeqNum());
                acknowledgeBytes = Packet.helper.getNormalPacketBytes(acknowledgePacket);
                client.addToSendPacketQueue(acknowledgeBytes);
                sender.setPhysicalKey(physicalKey);
//                System.out.println("new physical key set successfully!!!");
            }
            status = STATUS.FINISH;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void fileSenderOverflow() {
        status = STATUS.RUNNING;
        long time;
        byte[] sessionKey = new byte[16];
        new Random().nextBytes(sessionKey);
        try {
            Packet sessionKeyPacket = Packet.build.sessionKey(client.getName(), receiver.getClientName(), sessionKey, receiver.getPhysicalKey(), client.getServer().getPublicKey());
            byte[] sessionKeyBytes = Packet.helper.getNormalPacketBytes(sessionKeyPacket);
            client.addToSendPacketQueue(sessionKeyBytes);
//            System.out.println("overflow - breakpoint 1");
            Packet acknowledgePacket = Overflow.helper.getPacket(this);
            if (acknowledgePacket == null)
                return;
            receiver.setSessionKey(sessionKey);
//            System.out.println("session key sets successfully !!!");
            Packet fileConfigPacket = Packet.build.fileConfiguration(client.getName(), receiver.getClientName(), sessionKey, file);
            byte[] messageConfigPacketBytes = Packet.helper.getNormalPacketBytes(fileConfigPacket);
            client.addToSendPacketQueue(messageConfigPacketBytes);
            acknowledgePacket = Overflow.helper.getPacket(this);
            if (acknowledgePacket == null)
                return;
//            System.out.println("ready to send data!!!!");
            Integer packetCounts = Packet.helper.countFilePackets(file.length());
            byte[] fileArray = new byte[(int) file.length()];
            FileInputStream fis = new FileInputStream(file);
            fis.read(fileArray);
            for (int i = 0; i < packetCounts; i++) {
                byte[] data = null;
                if (i != packetCounts - 1) {
                    data = Arrays.copyOfRange(fileArray, (i * 25600), ((i + 1) * 25600));
                } else {
                    data = Arrays.copyOfRange(fileArray, i * 25600, fileArray.length);
                }
                Packet messagePacket = Packet.build.file(client.getName(), receiver.getClientName(), receiver.getSessionKey(), data, i);
                byte[] messagePacketBytes = Packet.helper.getFilePacketBytes(messagePacket);

                client.addToSendPacketQueue(messagePacketBytes);
                acknowledgePacket = Overflow.helper.getPacket(this);
                if (acknowledgePacket == null)
                    return;
                if (acknowledgePacket.getAckNum() == i) {
                    continue;
                } else {
                    sessionKey = new byte[16];
                    new Random().nextBytes(sessionKey);
                    sessionKeyPacket = Packet.build.sessionKey(client.getName(), receiver.getClientName(), sessionKey, receiver.getPhysicalKey(), client.getServer().getPublicKey());
                    sessionKeyBytes = Packet.helper.getNormalPacketBytes(sessionKeyPacket);
                    client.addToSendPacketQueue(sessionKeyBytes);
                    acknowledgePacket = Overflow.helper.getPacket(this);
                    if (acknowledgePacket == null)
                        return;
                    receiver.setSessionKey(sessionKey);
//                    System.out.println("session key has set again!!!!");
                    i -= 1;
                }
            }
//            System.out.println("message sent completely!!!!");
            byte[] physicalKey = new byte[32];
            new Random().nextBytes(physicalKey);
            Packet physicalKeyPacket = Packet.build.message(client.getName(), receiver.getClientName(), sessionKey, physicalKey, 0);
            byte[] physicalKeyPacketBytes = Packet.helper.getNormalPacketBytes(physicalKeyPacket);
            client.addToSendPacketQueue(physicalKeyPacketBytes);
            acknowledgePacket = Overflow.helper.getPacket(this);
            if (acknowledgePacket == null)
                return;
            receiver.setPhysicalKey(physicalKey);
//            System.out.println("session finished!!!");
            status = STATUS.FINISH;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static class TYPE {
        public static final int MESSAGE_SENDER_OVERFLOW = 1;
        public static final int MESSAGE_RECEIVER_OVERFLOW = 2;
        public static final int FILE_SENDER_OVERFLOW = 3;
    }

    public static class STATUS {
        public static final int CREATED = 1;
        public static final int RUNNING = 2;
        public static final int TERMINATE = 3;
        public static final int FINISH = 4;
    }

    public static class build {
        public static Overflow sender(Client client, ClientHandler receiver, String text) {
            Overflow overflow = new Overflow();
            overflow.type = TYPE.MESSAGE_SENDER_OVERFLOW;
            overflow.status = STATUS.CREATED;
            overflow.receivePackets = new LinkedList<>();
            overflow.client = client;
            overflow.receiver = receiver;
            overflow.text = text;
            return overflow;
        }

        public static Overflow receiver(Client client, ClientHandler sender) {
            Overflow overflow = new Overflow();
            overflow.type = TYPE.MESSAGE_RECEIVER_OVERFLOW;
            overflow.status = STATUS.CREATED;
            overflow.receivePackets = new LinkedList<>();
            overflow.client = client;
            overflow.sender = sender;
            return overflow;
        }

        public static Overflow fileSender(Client client, ClientHandler receiver, File file) {
            Overflow overflow = new Overflow();
            overflow.type = TYPE.FILE_SENDER_OVERFLOW;
            overflow.status = STATUS.CREATED;
            overflow.receivePackets = new LinkedList<>();
            overflow.client = client;
            overflow.receiver = receiver;
            overflow.file = file;
            return overflow;
        }
    }

    public static class helper {
        public static Packet getPacket(Overflow overflow) throws InterruptedException {
            Packet packet = null;
            long time = System.currentTimeMillis();
            while (true) {
                if (overflow.receivePackets.peek() != null) {
                    packet = overflow.receivePackets.remove();
                    break;
                }
                if (System.currentTimeMillis() - time > TIME_OUT) {
                    overflow.status = STATUS.TERMINATE;
                    System.out.println("session terminate");
                    break;
                }
                sleep(50);
            }
            return packet;
        }
    }

    public boolean addPacket(Packet packet) {
        try {
            receivePackets.add(packet);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    public int getStatus() {
        return status;
    }
}
