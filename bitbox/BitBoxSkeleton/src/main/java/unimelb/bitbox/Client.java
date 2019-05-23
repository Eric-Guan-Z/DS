package unimelb.bitbox;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.HostPort;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Base64;
import java.util.HashMap;
import java.util.logging.Logger;

public class Client {
    private static HashMap<Socket, BufferedWriter> socketWriter;
    private static HashMap<Socket, BufferedReader> socketReader;
    private static Logger log = Logger.getLogger(ServerMain.class.getName());
    private String[] args;
    private static HostPort hostPort;
    private static String pubk;
    private static String prik;
    private static final String EncryptAlg ="AES";
    private static final String Cipher_Mode="AES/ECB/PKCS7Padding";
    private static final String Encode="UTF-8";
    private static final int Secret_Key_Size=32;
    private static final String Key_Encode="UTF-8";

    public static void main(String[] args) {

        CMDReader argsBean = new CMDReader();

        //Parser provided by args4j
        CmdLineParser parser = new CmdLineParser(argsBean);
        try {

            //Parse the arguments
            parser.parseArgument(args);
            String command = argsBean.getCommand();
            String server = argsBean.getServer();
            String peer = argsBean.getPeer();

            switch (command) {

                case "connect_peer":
                    //TODO
                    break;

                case "list_peers":
                    //TODO
                    break;

                case "disconnect_peer":
                    //TODO
                    break;
            }

            System.out.println("command: " + command);
            System.out.println("server: " + server);
            System.out.println("peer: " + peer);

        } catch (CmdLineException e) {

            System.err.println(e.getMessage());

            //Print the usage to help the user understand the arguments expected
            //by the program
            parser.printUsage(System.err);
        }
    }

    private static String getSessionKey(){
        String sessionKey = null;
        String originalMessage = null;

        try {
            Socket client = new Socket(hostPort.host, hostPort.port);
            BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream(), "utf-8"));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(client.getOutputStream(), "utf-8"));

            sendInfo(constructAUTH_REQUEST(pubk), out);
            originalMessage = in.readLine();
            log.info(originalMessage);
        } catch (IOException e) {
            e.printStackTrace();
        }

        Document message = Document.parse(originalMessage);

            String encode_content = (String) message.get("AES128");
            ByteBuffer decode_content = ByteBuffer.wrap(Base64.decodeBase64(encode_content.getBytes()));
            try {
                sessionKey = aesPKCS7PaddingDecrypt(decode_content.toString(), prik);
            } catch (Exception e) {
                e.printStackTrace();
            }
        return sessionKey;
    }

    public static byte[] getSecretKey(String key) throws Exception{
        final byte paddingChar=' ';

        byte[] realKey = new byte[Secret_Key_Size];
        byte[] byteKey = key.getBytes(Key_Encode);
        for (int i =0;i<realKey.length;i++){
            if (i<byteKey.length){
                realKey[i] = byteKey[i];
            }else {
                realKey[i] = paddingChar;
            }
        }

        return realKey;
    }

    public static String aesPKCS7PaddingDecrypt(String content, String key) throws Exception {
        try {
            //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            byte[] decodeBytes=Base64.decodeBase64(content.getBytes());

            Cipher cipher = Cipher.getInstance(Cipher_Mode);
            byte[] realKey=getSecretKey(key);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(realKey,EncryptAlg));
            byte[] realBytes=cipher.doFinal(decodeBytes);

            return new String(realBytes, Encode);
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("AES Decryption Fail：Aescontent = " +e.fillInStackTrace(),e);
        }
    }

    private static Document constructAUTH_REQUEST(String pk) {
        Document request = new Document();
        request.append("command", "AUTH_REQUEST");
        request.append("identity", pk);
        return request;
    }


    private static void sendInfo(Document info, BufferedWriter out) {
        try {
            out.write(info.toJson());
            out.newLine();
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
