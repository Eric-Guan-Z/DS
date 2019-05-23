//package unimelb.bitbox;
//
//import javax.net.ServerSocketFactory;
//import java.io.BufferedReader;
//import java.io.BufferedWriter;
//import java.io.InputStreamReader;
//import java.io.OutputStreamWriter;
//import java.math.BigInteger;
//import java.net.ServerSocket;
//
//import java.net.Socket;
//import java.security.KeyFactory;
//import java.security.PublicKey;
//import java.security.spec.RSAPublicKeySpec;
//import java.util.Base64;
//import java.util.logging.Logger;
//public class test3 {
//    public static void main(String[] args) throws Exception{
//        ServerSocketFactory factory = ServerSocketFactory.getDefault();
//        ServerSocket socket = factory.createServerSocket(8113);
//        Socket client = socket.accept();
//        BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream(), "utf-8"));
//        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(client.getOutputStream(), "utf-8"));
//        String originalMessage;
//        while ((originalMessage = in.readLine()) != null) {
//            PublicKey pk = getPublicKey(keymap.get(identity));
//            String encoded = Base64.getEncoder().encodeToString(publicEnrypy(new String(encodedSKey), pk));
//        }
//    }
//    private static PublicKey getPublicKey(String identity)throws Exception{
//        byte[] load = Base64.getDecoder().decode(identity.getBytes());
//        byte[] exponentByt = subByte(load,15,3);
//        byte[] moduleLengthByt = subByte(load,18,4);
//
//        int moduleLengthInt = Integer.parseInt(bytes2HexString(moduleLengthByt),16);
//        BigInteger exponent = new BigInteger(bytes2HexString(exponentByt), 16);
//        byte[] moduleByt = subByte(load,22,moduleLengthInt);
//        BigInteger module = new BigInteger(bytes2HexString(moduleByt),16);
//
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        PublicKey pk = keyFactory.generatePublic(new RSAPublicKeySpec(module, exponent));
//        return pk;
//    }
//    private static byte[] subByte(byte[] b,int off,int length){
//        byte[] b1 = new byte[length];
//        System.arraycopy(b, off, b1, 0, length);
//        return b1;
//    }
//
//    private static String bytes2HexString(byte[] b) {
//        String r = "";
//
//        for (int i = 0; i < b.length; i++) {
//            String hex = Integer.toHexString(b[i] & 0xFF);
//            if (hex.length() == 1) {
//                hex = '0' + hex;
//            }
//            r += hex.toUpperCase();
//        }
//
//        return r;
//    }
//}
