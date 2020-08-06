package general;

import org.apache.commons.lang.ArrayUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Security {

    public static byte[] MAC(byte[] key, byte[] data) throws Exception{
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new Exception("Key length should be 16");
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "RawBytes");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }

    public static class AesCtr {
        private SecureRandom secureRandom;
        private SecretKeySpec secretKeySpec;
        private Cipher cipher;
        private int BLOCK_SIZE_BYTES = 16;

        public AesCtr(byte[] key) throws Exception {
            super();
            if (key.length != 16 && key.length != 24 && key.length != 32) {
                throw new Exception("Key length should be 16, 24, or 32 bytes long");
            }
            int KEY_SIZE_BYTES = key.length;
            secretKeySpec = new SecretKeySpec(key, "AES");
            cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            secureRandom = new SecureRandom();
        }

        public byte[] encrypt(byte[] data) throws Exception {
            if(data.length == 0) {
                throw new Exception("No data to encrypt");
            }
            byte[] iv = new byte[BLOCK_SIZE_BYTES];
            int BLOCK_SIZE_BITS = 128;
            byte[] randomNumber = (new BigInteger(BLOCK_SIZE_BITS, secureRandom)).toByteArray();
            int a;
            for(a = 0; a<randomNumber.length && a<BLOCK_SIZE_BYTES; a++)
                iv[a] = randomNumber[a];
            for(; a<BLOCK_SIZE_BYTES; a++)
                iv[a] = 0;
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
            return ArrayUtils.addAll(iv, cipher.doFinal(data));
        }

        public byte[] decrypt(byte[] data) throws Exception {
            return decrypt(data, 0);
        }

        public byte[] decrypt(byte[] data, int offset) throws Exception {
            if(data.length <= BLOCK_SIZE_BYTES + offset) {
                throw new Exception("No data to decrypt");
            }
            byte[] iv = new byte[BLOCK_SIZE_BYTES];
            System.arraycopy(data, offset, iv, 0, BLOCK_SIZE_BYTES);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
            return cipher.doFinal(data, (BLOCK_SIZE_BYTES + offset), data.length - (BLOCK_SIZE_BYTES + offset));
        }


    }

    public static class RSA {
        public static KeyPair keyPairGenerator() throws NoSuchAlgorithmException {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            return keyGen.generateKeyPair();
        }

        public static byte[] encrypt (PublicKey publicKey, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            if (data.length > 117) {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                int i = 0;
                while (i < data.length) {
                    if (i + 117 < data.length) {
                        outputStream.write(cipher.doFinal(Arrays.copyOfRange(data, i, i + 117)));
                        i += 117;
                    } else {
                        outputStream.write(cipher.doFinal(Arrays.copyOfRange(data, i, data.length)));
                        i = data.length;
                    }
                }
                return outputStream.toByteArray();
            } else
                return cipher.doFinal(data);
        }

        public static byte[] decrypt (PrivateKey privateKey, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            if (data.length > 128) {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                int i = 0;
                while (i < data.length) {
                    if (i + 128 < data.length) {
                        outputStream.write(cipher.doFinal(Arrays.copyOfRange(data, i, i + 128)));
                        i += 128;
                    } else {
                        outputStream.write(cipher.doFinal(Arrays.copyOfRange(data, i, data.length)));
                        i = data.length;
                    }
                }
                return outputStream.toByteArray();
            } else
                return cipher.doFinal(data);
        }

        public static PublicKey getPublicKeyFromStr(String publicKeyStr) {
            PublicKey publicKey;
            KeyFactory keyFactory = null;
            try {
                keyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                System.out.println("No such algorithm exist");
                return null;
            }
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            try {
                publicKey = keyFactory.generatePublic(keySpec);
                return publicKey;
            } catch (InvalidKeySpecException e) {
                System.out.println("Key spec error");
                return null;
            }
        }

        public static PublicKey getPublicKeyFromBytes(byte[] publicKeyBytes) {
            PublicKey publicKey;
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                publicKey = keyFactory.generatePublic(keySpec);
                return publicKey;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return null;
            }
        }

        public static String getPublicKeyStr(PublicKey publicKey) {
            byte[] byte_pubkey = publicKey.getEncoded();
            String str_key = Base64.getEncoder().encodeToString(byte_pubkey);
            return str_key;
        }

        public static byte[] getPublicKeyBytes(PublicKey publicKey) {
            return publicKey.getEncoded();
        }
    }
}
