package fp.dam.psp.servidorcontactos.cliente;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class Main {
    //Para hacer format el atajo es CTRL+ALT+L

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 9000)) {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Leer certificado enviado por el servidor
            String b64Certificate = in.readUTF();
            byte[] certificateBytes = Base64.getDecoder().decode(b64Certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBytes));

            // Modificar este bloque de código para generar la clave según se explica en
            // https://www.baeldung.com/java-aes-encryption-decryption usando el algoritmo
            // de derivación de clave PBKDF2WithHmacSHA256.
            // Se enviará el vector de inicialización (iv) usado por el algoritmo "AES/GCM/NoPadding" en lugar del algoritmo (linea 48).

            // Crear clave secreta.
            SecretKey key = getKeyFromPassword("iesdoctorFleming");
            // Cifrar la clave secreta con la clave pública del servidor
            Cipher cipher = Cipher.getInstance(certificate.getPublicKey().getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
            byte[] encriptedKey = cipher.doFinal(key.getEncoded());
            // Enviar al servidor la clave secreta cifrada y codificada en Base64
            out.writeUTF(Base64.getEncoder().encodeToString(encriptedKey));
            // Enviar al servidor el vector de inicializacion
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            out.writeUTF(Base64.getEncoder().encodeToString(iv));

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

    public static SecretKey getKeyFromPassword(String password)
            throws GeneralSecurityException {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
        return secret;
    }

}
