package fp.dam.psp.servidorcontactos.cliente;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
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
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 9000)) {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // ---- Leer certificado enviado por el servidor
            String b64Certificate = in.readUTF();
            byte[] certificateBytes = Base64.getDecoder().decode(b64Certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBytes));

            // ---- Crear clave secreta
            SecretKey key = getKeyFromPassword("iesdoctorFleming");

            // ---- Cifrar la clave secreta con la clave pública del servidor
            Cipher cipher = Cipher.getInstance(certificate.getPublicKey().getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
            byte[] encryptedKey = cipher.doFinal(key.getEncoded());

            // ---- Enviar la clave secreta cifrada al servidor
            out.writeUTF(Base64.getEncoder().encodeToString(encryptedKey));

            // ---- Enviar el vector de inicialización
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            out.writeUTF(Base64.getEncoder().encodeToString(iv));

            // ---- Leer la petición del cliente desde el teclado
            Scanner scanner = new Scanner(System.in);
            System.out.println("Introduce tu petición (listar, buscar:<nombre>, eliminar:<nombre>, añadir:<nombre>:<telefono>):");
            String peticion = scanner.nextLine();

            // ---- Cifrar la petición usando AES/GCM/NoPadding con IV
            Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
            byte[] encryptedPeticion = encryptCipher.doFinal(peticion.getBytes(StandardCharsets.UTF_8));

            // ---- Enviar la petición cifrada al servidor
            out.writeUTF(Base64.getEncoder().encodeToString(encryptedPeticion));

            // ---- Leer y descifrar la respuesta del servidor
            byte[] respuestaCifrada = Base64.getDecoder().decode(in.readUTF());
            Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
            String respuesta = new String(decryptCipher.doFinal(respuestaCifrada), StandardCharsets.UTF_8);

            // ---- Mostrar la respuesta del servidor
            System.out.println("Respuesta del servidor: " + respuesta);


        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public static SecretKey getKeyFromPassword(String password) throws GeneralSecurityException {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }
}