package general;

import com.sun.xml.internal.bind.v2.runtime.reflect.Lister;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.print.DocFlavor;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Packet {
    private String sourceName; // 16 fixed byte array
    private String destName; // 16 fixed byte array
    private Integer seqNum; // 4 fixed byte array
    private Integer ackNum; // 4 fixed byte array
    private int type; // 4 fixed byte array
    private byte[] data; // 50kB for data packets - 2kB for other packet type
    private Integer dataOffset; // 4 fixed byte array
    private byte[] MAC; // MAC hashes to 32 fixed byte array
    private String option; // 8 fixed byte array

    public static int PACKET_SIZE = 2136;
    public static int MESSAGE_DATA_SIZE = 2048;
    public static int FILE_PACKET_SIZE = 51288;
    public static int FILE_DATA_SIZE = 51200;

    public static class build {
        private static int DEFAULT_ACKNUM = 1;
        private static int DEFAULT_SEQNUM = 1;
        private static String DEFAULT_OPTION = "";

        public static Packet clientInitialize(String clientName, PublicKey clientPublicKey, PublicKey serverPublicKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
            Packet packet = new Packet();
            packet.sourceName = clientName;
            packet.destName = "server";
            packet.seqNum = 1;
            packet.ackNum = 1;
            packet.type = TYPE.CLIENT_INITIALIZE;
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(clientName.getBytes());
            byteArrayOutputStream.write(new byte[]{0});
            byteArrayOutputStream.write(Security.RSA.getPublicKeyBytes(clientPublicKey));
            packet.data = Security.RSA.encrypt(serverPublicKey, byteArrayOutputStream.toByteArray());
            packet.dataOffset = packet.data.length;
            packet.MAC = new byte[32];
            packet.option = "";
            return packet;
        }

        public static Packet setDefaultPhysicalKey(String destName, byte[] physicalKey, PublicKey clientPublicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
            Packet packet = new Packet();
            packet.sourceName = "server";
            packet.destName = destName;
            packet.ackNum = DEFAULT_ACKNUM;
            packet.seqNum = DEFAULT_SEQNUM;
            packet.type = TYPE.SET_PHYSICAL_KEY;
            packet.data = Security.RSA.encrypt(clientPublicKey, physicalKey);
            packet.dataOffset = packet.data.length;
            packet.MAC = new byte[32];
            packet.option = "";
            return packet;
        }

        public static Packet sessionKey(String clientName, String destName, byte[] sessionKey, byte[] physicalKey, PublicKey serverPublicKey) throws Exception {
            Packet packet = new Packet();
            packet.sourceName = clientName;
            packet.destName = destName;
            packet.seqNum = DEFAULT_SEQNUM;
            packet.ackNum = DEFAULT_ACKNUM;
            packet.type = TYPE.SESSION_KEY;
            Security.AesCtr aesCtr = new Security.AesCtr(physicalKey);
            byte[] encryptedSessionKey = aesCtr.encrypt(sessionKey);
            byte[] data = Security.RSA.encrypt(serverPublicKey, encryptedSessionKey);
            packet.data = data;
            packet.dataOffset = packet.data.length;
            packet.MAC = new byte[32];
            packet.option = "";
            return packet;
        }

        public static Packet acknowledgement(String sourceName, String destName, int ackNum) {
            Packet packet = new Packet();
            packet.sourceName = sourceName;
            packet.destName = destName;
            packet.seqNum = 1;
            packet.ackNum = ackNum;
            packet.type = TYPE.ACKNOWLEDGEMENT;
            packet.data = new byte[2048];
            packet.dataOffset = 0;
            packet.MAC = new byte[32];
            packet.option = "";
            return packet;
        }

        public static Packet messageConfiguration(String clientName, String destName, byte[] sessionKey, int messageLength) throws Exception {
            Packet packet = new Packet();
            packet.sourceName = clientName;
            packet.destName = destName;
            packet.ackNum = DEFAULT_ACKNUM;
            packet.seqNum = DEFAULT_SEQNUM;
            packet.option = DEFAULT_OPTION;
            int packetCount = Packet.helper.countMessagePackets(messageLength);
            byte[] data = Integer.toString(packetCount).getBytes();
            Security.AesCtr aesCtr = new Security.AesCtr(sessionKey);
            byte[] encryptedData = aesCtr.encrypt(data);
            packet.data = encryptedData;
            packet.dataOffset = packet.data.length;
            packet.MAC = Security.MAC(sessionKey, data);
            packet.type = TYPE.MESSAGE_CONFIGURATION;
            return packet;
        }

        public static Packet fileConfiguration(String clientName, String destName, byte[] sessionKey, File file) throws Exception {
            Packet packet = new Packet();
            packet.sourceName = clientName;
            packet.destName = destName;
            packet.ackNum = DEFAULT_ACKNUM;
            packet.seqNum = DEFAULT_SEQNUM;
            packet.option = DEFAULT_OPTION;
            packet.type = TYPE.FILE_CONFIGURATION;
            String fileName = file.getName();
            int packetCount = Packet.helper.countFilePackets(file.length());
            byte[] data = helper.encodeFilePacketConfig(packetCount, fileName).getBytes();
            Security.AesCtr aesCtr = new Security.AesCtr(sessionKey);
            byte[] encryptedData = aesCtr.encrypt(data);
            packet.data = encryptedData;
            packet.dataOffset = packet.data.length;
            packet.MAC = Security.MAC(sessionKey, data);
            return packet;
        }

        public static Packet message(String clientName, String destName, byte[] sessionKey, byte[] data, int seqNum) throws Exception {
            Packet packet = new Packet();
            packet.sourceName = clientName;
            packet.destName = destName;
            packet.option = DEFAULT_OPTION;
            packet.ackNum = DEFAULT_ACKNUM;
            packet.seqNum = seqNum;
            packet.type = TYPE.MESSAGE;
            Security.AesCtr aesCtr = new Security.AesCtr(sessionKey);
            List<byte[]> encryptedData = new ArrayList<>();
            int packetEncryptedDataSize = 0;
            int blockCount = data.length / 16;
            if (data.length % 16 != 0)
                blockCount += 1;
            for (int i = 0; i < blockCount; i++) {
                byte[] encryptedBlock = null;
                if (i != blockCount - 1)
                    encryptedBlock = aesCtr.encrypt(Arrays.copyOfRange(data, i * 16, (i + 1) * 16));
                else
                    encryptedBlock = aesCtr.encrypt(Arrays.copyOfRange(data, i * 16, data.length));
                encryptedData.add(encryptedBlock);
                packetEncryptedDataSize += encryptedBlock.length;
            }
            byte[] packetEncryptedData = new byte[packetEncryptedDataSize];
            int temp = 0;
            for (int i = 0; i < encryptedData.size(); i++) {
                System.arraycopy(encryptedData.get(i), 0, packetEncryptedData, temp, encryptedData.get(i).length);
                temp += encryptedData.get(i).length;
            }
            packet.data = packetEncryptedData;
            packet.dataOffset = packet.data.length;
            packet.MAC = Security.MAC(sessionKey, data);
            return packet;
        }

        public static Packet file(String clientName, String destName, byte[] sessionKey, byte[] data, int seqNum) throws Exception {
            Packet packet = new Packet();
            packet.sourceName = clientName;
            packet.destName = destName;
            packet.option = DEFAULT_OPTION;
            packet.ackNum = DEFAULT_ACKNUM;
            packet.seqNum = seqNum;
            packet.type = TYPE.FILE;
            Security.AesCtr aesCtr = new Security.AesCtr(sessionKey);
            List<byte[]> encryptedData = new ArrayList<>();
            int packetEncryptedDataSize = 0;
            int blockCount = data.length / 16;
            if (data.length % 16 != 0)
                blockCount += 1;
            for (int i = 0; i < blockCount; i++) {
                byte[] encryptedBlock = null;
                if (i != blockCount - 1)
                    encryptedBlock = aesCtr.encrypt(Arrays.copyOfRange(data, i * 16, (i + 1) * 16));
                else
                    encryptedBlock = aesCtr.encrypt(Arrays.copyOfRange(data, i * 16, data.length));
                encryptedData.add(encryptedBlock);
                packetEncryptedDataSize += encryptedBlock.length;
            }
            byte[] packetEncryptedData = new byte[packetEncryptedDataSize];
            int temp = 0;
            for (int i = 0; i < encryptedData.size(); i++) {
                System.arraycopy(encryptedData.get(i), 0, packetEncryptedData, temp, encryptedData.get(i).length);
                temp += encryptedData.get(i).length;
            }
            packet.data = packetEncryptedData;
            packet.dataOffset = packet.data.length;
            packet.MAC = Security.MAC(sessionKey, data);
            return packet;
        }
    }

    public static class helper {
        public static byte[] getNormalPacketBytes(Packet packet) throws IOException {
            try {
                byte[] sourceName = new byte[16];
                System.arraycopy(packet.sourceName.getBytes(), 0, sourceName, 0, packet.sourceName.length());
                byte[] destName = new byte[16];
                System.arraycopy(packet.destName.getBytes(), 0, destName, 0, packet.destName.length());
                byte[] seqNum = ByteBuffer.allocate(4).putInt(packet.seqNum).array();
                byte[] ackNum = ByteBuffer.allocate(4).putInt(packet.ackNum).array();
                byte[] type = ByteBuffer.allocate(4).putInt(packet.type).array();
                byte[] data = new byte[2048];
                System.arraycopy(packet.data, 0, data, 0, packet.data.length);
                byte[] dataOffset = ByteBuffer.allocate(4).putInt(packet.dataOffset).array();
                byte[] MAC = new byte[32];
                System.arraycopy(packet.MAC, 0, MAC, 0, packet.MAC.length);
                byte[] opetion = new byte[8];
                System.arraycopy(packet.option.getBytes(), 0, opetion, 0, packet.option.length());

                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(sourceName);
                outputStream.write(destName);
                outputStream.write(seqNum);
                outputStream.write(ackNum);
                outputStream.write(type);
                outputStream.write(data);
                outputStream.write(dataOffset);
                outputStream.write(MAC);
                outputStream.write(opetion);
                return outputStream.toByteArray();
            } catch (Exception e) {
                System.out.println("HELLLLLO");
                return null;
            }
        }

        public static byte[] getFilePacketBytes(Packet packet) throws IOException {
            byte[] sourceName = new byte[16];
            System.arraycopy(packet.sourceName.getBytes(), 0, sourceName, 0, packet.sourceName.length());
            byte[] destName = new byte[16];
            System.arraycopy(packet.destName.getBytes(), 0, destName, 0, packet.destName.length());
            byte[] seqNum = ByteBuffer.allocate(4).putInt(packet.seqNum).array();
            byte[] ackNum = ByteBuffer.allocate(4).putInt(packet.ackNum).array();
            byte[] type = ByteBuffer.allocate(4).putInt(packet.type).array();
            byte[] data = new byte[Packet.FILE_DATA_SIZE];
            System.arraycopy(packet.data, 0, data, 0, packet.data.length);
            byte[] dataOffset = ByteBuffer.allocate(4).putInt(packet.dataOffset).array();
            byte[] MAC = new byte[32];
            System.arraycopy(packet.MAC, 0, MAC, 0, packet.MAC.length);
            byte[] opetion = new byte[8];
            System.arraycopy(packet.option.getBytes(), 0, opetion, 0, packet.option.length());

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(sourceName);
            outputStream.write(destName);
            outputStream.write(seqNum);
            outputStream.write(ackNum);
            outputStream.write(type);
            outputStream.write(data);
            outputStream.write(dataOffset);
            outputStream.write(MAC);
            outputStream.write(opetion);
            return outputStream.toByteArray();
        }

        public static Packet getNormalPacket(byte[] packet) {
            Packet resultPacket = new Packet();
            byte[] sourceName = Arrays.copyOfRange(packet, 0, 16);
            byte[] destName = Arrays.copyOfRange(packet, 16, 32);
            byte[] seqNum = Arrays.copyOfRange(packet, 32, 36);
            byte[] ackNum = Arrays.copyOfRange(packet, 36, 40);
            byte[] type = Arrays.copyOfRange(packet, 40, 44);
            byte[] data = Arrays.copyOfRange(packet, 44, 2092);
            byte[] dataOffset = Arrays.copyOfRange(packet, 2092, 2096);
            byte[] MAC = Arrays.copyOfRange(packet, 2096, 2128);
            byte[] option = Arrays.copyOfRange(packet, 2128, 2136);

            resultPacket.sourceName = new String(sourceName).trim();
            resultPacket.destName = new String(destName).trim();
            resultPacket.seqNum = ByteBuffer.wrap(seqNum).getInt();
            resultPacket.ackNum = ByteBuffer.wrap(ackNum).getInt();
            resultPacket.type = ByteBuffer.wrap(type).getInt();
            resultPacket.dataOffset = ByteBuffer.wrap(dataOffset).getInt();
            resultPacket.data = Arrays.copyOfRange(data, 0, resultPacket.dataOffset);
            resultPacket.MAC = MAC;
            resultPacket.option = new String(option).trim();
            return resultPacket;
        }

        public static Packet getFilePacket(byte[] packet) {
            Packet resultPacket = new Packet();
            byte[] sourceName = Arrays.copyOfRange(packet, 0, 16);
            byte[] destName = Arrays.copyOfRange(packet, 16, 32);
            byte[] seqNum = Arrays.copyOfRange(packet, 32, 36);
            byte[] ackNum = Arrays.copyOfRange(packet, 36, 40);
            byte[] type = Arrays.copyOfRange(packet, 40, 44);
            byte[] data = Arrays.copyOfRange(packet, 44, 51244);
            byte[] dataOffset = Arrays.copyOfRange(packet, 51244, 51248);
            byte[] MAC = Arrays.copyOfRange(packet, 51248, 51280);
            byte[] option = Arrays.copyOfRange(packet, 51280, 51288);

            resultPacket.sourceName = new String(sourceName).trim();
            resultPacket.destName = new String(destName).trim();
            resultPacket.seqNum = ByteBuffer.wrap(seqNum).getInt();
            resultPacket.ackNum = ByteBuffer.wrap(ackNum).getInt();
            resultPacket.type = ByteBuffer.wrap(type).getInt();
            resultPacket.dataOffset = ByteBuffer.wrap(dataOffset).getInt();
            resultPacket.data = Arrays.copyOfRange(data, 0, resultPacket.dataOffset);
            resultPacket.MAC = MAC;
            resultPacket.option = new String(option).trim();
            return resultPacket;
        }

        public static boolean checkMAC(Packet packet, byte[] sessionKey) throws Exception {
            Security.AesCtr aesCtr = new Security.AesCtr(sessionKey);
            byte[] decryptedData = getPacketData(packet, sessionKey);
            byte[] predictedMAC = Security.MAC(sessionKey, decryptedData);
            return Arrays.equals(predictedMAC, packet.MAC);
        }

        public static int countMessagePackets(int messageLength) {
            int blockCount = (int) (messageLength / 16);
            if (messageLength % 16 != 0)
                blockCount += 1;
            int encryptedDataSize = blockCount * 32;
            int packetCount = (int) (encryptedDataSize / MESSAGE_DATA_SIZE);
            if (encryptedDataSize % MESSAGE_DATA_SIZE != 0)
                packetCount += 1;
            return packetCount;
        }

        public static int countFilePackets(long fileLength) {
            long blockCount = (long) (fileLength / 16);
            if (fileLength % 16 != 0)
                blockCount += 1;
            long encryptedDataSize = blockCount * 32;
            int packetCount = (int) (encryptedDataSize / FILE_DATA_SIZE);
            if (encryptedDataSize % FILE_DATA_SIZE != 0)
                packetCount += 1;
            return packetCount;
        }

        public static byte[] getPacketData(Packet packet, byte[] sessionKey) throws Exception {
            int temp = 0;
            List<byte[]> blockData = new ArrayList<>();
            Security.AesCtr aesCtr = new Security.AesCtr(sessionKey);
            byte[] data = null;
            int blockCount = packet.dataOffset / 32;
            if (packet.dataOffset % 32 != 0)
                blockCount += 1;
            for (int i = 0; i < blockCount; i++) {
                byte[] decryptedData = null;
                if (i != blockCount - 1)
                    decryptedData = aesCtr.decrypt(Arrays.copyOfRange(packet.data, i * 32, (i + 1) * 32));
                else
                    decryptedData = aesCtr.decrypt(Arrays.copyOfRange(packet.data, i * 32, packet.dataOffset));
                blockData.add(decryptedData);
                temp += decryptedData.length;
            }
            data = new byte[temp];
            for (int i = 0; i < blockCount; i++) {
                System.arraycopy(blockData.get(i), 0, data, i * 16, blockData.get(i).length);
            }
            return data;
        }

        public static String encodeFilePacketConfig(int packetCount, String fileName) {
            StringBuilder config = new StringBuilder();
            config.append(Integer.toString(packetCount));
            config.append("#");
            config.append(fileName);
            return config.toString();
        }

        public static String[] decodeFilePacketConfig(String encodeConfig) {
            return encodeConfig.split("#");
        }
    }

    public static class TYPE {
        public static int CLIENT_INITIALIZE = 1;
        public static int SESSION_KEY = 2;
        public static int ACKNOWLEDGEMENT = 3;
        public static int MESSAGE_CONFIGURATION = 4;
        public static int FILE_CONFIGURATION = 5;
        public static int MESSAGE = 6;
        public static int FILE = 7;
        public static int SET_PHYSICAL_KEY = 8;
    }

    public String getSourceName() {
        return sourceName;
    }

    public void setSourceName(String sourceName) {
        this.sourceName = sourceName;
    }

    public String getDestName() {
        return destName;
    }

    public void setDestName(String destName) {
        this.destName = destName;
    }

    public Integer getSeqNum() {
        return seqNum;
    }

    public void setSeqNum(Integer seqNum) {
        this.seqNum = seqNum;
    }

    public Integer getAckNum() {
        return ackNum;
    }

    public void setAckNum(Integer ackNum) {
        this.ackNum = ackNum;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public Integer getDataOffset() {
        return dataOffset;
    }

    public void setDataOffset(Integer dataOffset) {
        this.dataOffset = dataOffset;
    }

    public byte[] getMAC() {
        return MAC;
    }

    public void setMAC(byte[] MAC) {
        this.MAC = MAC;
    }

    public String getOption() {
        return option;
    }

    public void setOption(String option) {
        this.option = option;
    }
}
