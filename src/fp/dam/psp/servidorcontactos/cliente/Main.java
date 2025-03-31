package fp.dam.psp.servidorcontactos.cliente;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 9000)) {
            Base64.Decoder decoder = Base64.getDecoder();
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Leer certificado enviado por el servidor
            String b64Certificate = in.readUTF();
            byte[] certificateBytes = decoder.decode(b64Certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBytes));
            PublicKey publicKey = certificate.getPublicKey();

            // Crear clave secreta, cifrarla y enviarla al servidor
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey key = kg.generateKey();
            Cipher cipher = Cipher.getInstance(certificate.getPublicKey().getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte [] encriptedKey = cipher.doFinal(key.getEncoded());
            Base64.Encoder encoder = Base64.getEncoder();
            out.writeUTF(encoder.encodeToString(encriptedKey));

            // Enviar al servidor el algoritmo de cifrado simétrico
            out.writeUTF("AES");

            // Prueba descifrado
            Cipher sCipher = Cipher.getInstance("AES");
            sCipher.init(Cipher.DECRYPT_MODE, key);
            String mensaje = new String(sCipher.doFinal(decoder.decode(in.readUTF())));
            System.out.println(mensaje);
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

}
