package fp.dam.psp.servidorcontactos.cliente;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 9000)) {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Leer certificado enviado por el servidor
            String b64Certificate = in.readUTF();
            byte[] certificateBytes = Base64.getDecoder().decode(b64Certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBytes));
            PublicKey publicKey = certificate.getPublicKey();

            // Crear clave secreta.
            // Modificar el siguiente código para generar la clave según se explica en
            // https://www.baeldung.com/java-aes-encryption-decryption usando el algoritmo
            // de derivación de clave PBKDF2WithHmacSHA256.
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey key = kg.generateKey();
            // Cifrar la clave secreta con la clave pública del servidor
            Cipher cipher = Cipher.getInstance(certificate.getPublicKey().getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte [] encriptedKey = cipher.doFinal(key.getEncoded());
            // Enviar al servidor la clave secreta cifrada y codificada en Base64
            out.writeUTF(Base64.getEncoder().encodeToString(encriptedKey));
            // Enviar al servidor el algoritmo
            // Modificar este código para enviar el algoritmo "AES/GCM/NoPadding" y los parámetros adicionales.
            out.writeUTF("AES");

            // Realizar petición
            String peticion = "hola servidor";
            // Modificar el siguiente código para cifrar usando "AES/GCM/NoPadding" tal y como se explica en
            // https://www.baeldung.com/java-aes-encryption-decryption
            Cipher encrypCipher = Cipher.getInstance("AES");
            encrypCipher.init(Cipher.ENCRYPT_MODE, key);
            out.writeUTF(Base64.getEncoder().encodeToString(encrypCipher.doFinal(peticion.getBytes(StandardCharsets.UTF_8))));
            Cipher decrypCipher = Cipher.getInstance("AES");
            decrypCipher.init(Cipher.DECRYPT_MODE, key);
            String respuesta = new String(decrypCipher.doFinal(Base64.getDecoder().decode(in.readUTF())));
            System.out.println(respuesta);
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

}
