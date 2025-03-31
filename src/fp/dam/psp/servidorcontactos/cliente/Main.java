package fp.dam.psp.servidorcontactos.cliente;

import javax.crypto.*;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 9000)) {
            Base64.Decoder decoder = Base64.getDecoder();
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            //Leer certificado enviado por el servidor
            String b64Certificate = in.readUTF();
            byte[] certificateBytes = decoder.decode(b64Certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBytes));
            PublicKey publicKey = certificate.getPublicKey();
            //System.out.println(certificate.getSubjectX500Principal().getName());

            //Crear clave secreta, cifrarla y enviarla al servidor
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey key = kg.generateKey();
            Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm()+"/ECB/PKCS5Padding");
            byte[] encriptedKey = cipher.doFinal(key.getEncoded());
            Base64.Encoder encoder = Base64.getEncoder();
            out.writeUTF(encoder.encodeToString(encriptedKey));

            //Enviar al servidor el algoritmo de cifrado simetrico
            out.writeUTF("AES/ECB/PKCS5Padding");


        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

}
