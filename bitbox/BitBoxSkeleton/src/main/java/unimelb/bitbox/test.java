package unimelb.bitbox;
import javax.crypto.Cipher;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;


import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;



public class test {

    public static byte[] readFileBytes(String filename) throws IOException
    {
        Path path = Paths.get(filename);

        return Files.readAllBytes(path);
    }

    public static PublicKey readPublicKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        FileInputStream fis = new FileInputStream("id_rsa.pub");
        BASE64Decoder decoder = new BASE64Decoder();
        byte[] encodeByte = decoder.decodeBuffer(fis);
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(encodeByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(publicSpec);
    }

    public static PrivateKey readPrivateKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(readFileBytes(filename));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static byte[] publicEnrypy(String express,PublicKey pub) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pub);// 设置为加密模式
        byte[] result = cipher.doFinal(express.getBytes());// 对数据进行加密
        return result;//返回密文
    }

    public static byte[] privateEncode(byte[] cipherText, PrivateKey priv) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priv);//设置为解密模式，用私钥解密
        byte[] result = cipher.doFinal(cipherText);//对加密后的数据进行解密

        return result ;//返回明文
    }

    public static void main(String[] args) {
        PublicKey pub;
        PrivateKey priv;
        String origin;

        origin = "aaabbbccc";
        try {
            FileInputStream fis = new FileInputStream("id_rsa.pub");
            BASE64Decoder decoder = new BASE64Decoder();
            byte[] encodeByte = decoder.decodeBuffer(fis);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(encodeByte);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            pub = keyFactory.generatePublic(publicSpec);
            priv = readPrivateKey("id_rsa");
            String result = new String(privateEncode(publicEnrypy(origin, pub), priv));
            System.out.println(result);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
//        try {
//            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(readFileBytes("id_rsa"));
//        } catch (IOException e) {
//            e.printStackTrace();
//        }


    }
}
