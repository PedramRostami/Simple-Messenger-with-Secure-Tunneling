package client;

import java.sql.Timestamp;

public class ClientHandler {
    private String clientName;
    private byte[] physicalKey;
    private byte[] sessionKey;
    private long sessionKeyExpiration;

    public ClientHandler(String clientName, byte[] physicalKey) {
        this.clientName = clientName;
        this.physicalKey = physicalKey;
    }

    public String getClientName() {
        return clientName;
    }


    public byte[] getPhysicalKey() {
        return physicalKey;
    }

    public void setPhysicalKey(byte[] physicalKey) {
        this.physicalKey = physicalKey;
    }

    public byte[] getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(byte[] sessionKey) {
        this.sessionKey = sessionKey;
    }

    public long getSessionKeyExpiration() {
        return sessionKeyExpiration;
    }

    public void setSessionKeyExpiration(long sessionKeyExpiration) {
        this.sessionKeyExpiration = sessionKeyExpiration;
    }

    public void setDefaultSessionExpiration() {
        this.sessionKeyExpiration = System.currentTimeMillis() + 14000000;
    }
}
