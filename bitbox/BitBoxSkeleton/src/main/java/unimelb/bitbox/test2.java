package unimelb.bitbox;

import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;
import sun.misc.BASE64Decoder;
import unimelb.bitbox.util.Configuration;
import java.security.KeyFactory;
import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;

public class test2 {
    public static void main(String[] args) throws Exception{
//        String[] keysInfo = Configuration.getConfigurationValue("authorized_keys").split(",");
//        HashMap<String, String> keymap = new HashMap<>();
//        for (String pk : keysInfo){
//            String[] items = pk.split(" ");
//            keymap.put(items[2], items[1]);
//        }
//        System.out.println(keymap);
        String identity ="AAAAB3NzaC1yc2EAAAADAQABAAABAQC1iKVLzPfXSs9NjT2oUkAAVnRqjbq8VFfMjdNhHJM1O2/IBLtwcufMI8DjOlNAYQeD2JvixYFMzeAuGddG3v47P12d5CY/MUKtBTJjVUmWEFziG3DFHZmFJnRfGNj+zbo9pPHXai7N+yqH2WMqEGWPOJjMBFnLgGNHT1ltJ8jgZNkRmVjsc8TlYWfIGRGakuAch8TTwM2fXjxp5lCJrgO0hnf4j1guns6bacGqK0lNP6SZzSA1jmqqV1+z0daRIn+M+eqYVXpZN0W2zTSwwlIhSrbbMXLW1ri/XboIRYhQOJtfus5kzyTgzDpjyHHGP8qyCrJItIkbDhs7wYcyjGJX";
        byte[] load = Base64.getDecoder().decode(identity.getBytes());
        byte[] exponentByt = subByte(load,15,3);
        byte[] moduleLengthByt = subByte(load,18,4);

        int moduleLengthInt = Integer.parseInt(bytes2HexString(moduleLengthByt),16);
        BigInteger exponent = new BigInteger(bytes2HexString(exponentByt), 16);
        byte[] moduleByt = subByte(load,22,moduleLengthInt);
        BigInteger module = new BigInteger(bytes2HexString(moduleByt),16);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pk = keyFactory.generatePublic(new RSAPublicKeySpec(module, exponent));

        String sessionKey = getRandomSessionKey(32);
        System.out.println(identity.length());

        String encoded = Base64.getEncoder().encodeToString(publicEnrypy(sessionKey, pk));

        System.out.println(encoded);


    }

    public static byte[] publicEnrypy(String express,PublicKey pub) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pub);// 设置为加密模式
        byte[] result = cipher.doFinal(express.getBytes());// 对数据进行加密
        return result;//返回密文
    }

    public static String getRandomSessionKey(int length){
        String str="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random=new Random();
        StringBuffer sb=new StringBuffer();
        for(int i=0;i<length;i++){
            int number=random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public static byte[] subByte(byte[] b,int off,int length){
        byte[] b1 = new byte[length];
        System.arraycopy(b, off, b1, 0, length);
        return b1;
    }

    public static String bytes2HexString(byte[] b) {
        String r = "";

        for (int i = 0; i < b.length; i++) {
            String hex = Integer.toHexString(b[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            r += hex.toUpperCase();
        }

        return r;
    }

}
