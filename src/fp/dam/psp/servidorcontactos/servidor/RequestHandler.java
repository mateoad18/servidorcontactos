package fp.dam.psp.servidorcontactos.servidor;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;

public class RequestHandler implements Runnable {

    private final Socket socket;
    private final X509Certificate certificate;
    private final PrivateKey privateKey;
    private final Base64.Encoder encoder = Base64.getEncoder();
    private final Base64.Decoder decoder = Base64.getDecoder();
    private DataInputStream in;
    private DataOutputStream out;
    private Cipher encryptCipher;
    private Cipher decryptCipher;

    public RequestHandler(Socket socket, X509Certificate certificate, PrivateKey privateKey) throws IOException {
        this.socket = socket;
        this.certificate = certificate;
        this.privateKey = privateKey;
        socket.setSoTimeout(10000);
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());
    }

    @Override
    public void run() {
        try (socket) {
            // Enviar el certificado del servidor codificado en Base64
            out.writeUTF(encoder.encodeToString(certificate.getEncoded()));

            // Crear un Cipher para descifrar la clave secreta que enviará el cliente
            // con la clave privada del servidor
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Leer clave secreta cifrada enviada por el cliente, decodificar B64 y descifrarla
            byte[] encodedKey = cipher.doFinal(decoder.decode(in.readUTF()));
            String algorithm = in.readUTF();
            // Decodificarla como un objeto SecretKey
            SecretKey key = new SecretKeySpec(encodedKey, algorithm);

            // Crear los Cipher para cifrar y descifrar con la clave secreta
            encryptCipher = Cipher.getInstance(algorithm);
            encryptCipher.init(Cipher.ENCRYPT_MODE, key);
            decryptCipher = Cipher.getInstance(algorithm);
            decryptCipher.init(Cipher.DECRYPT_MODE, key);

            leerPeticion();
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error: " + e.getLocalizedMessage() + " : " +
                    socket.getInetAddress() + " : " + LocalDateTime.now());
        }
    }

    void leerPeticion() throws IOException, IllegalBlockSizeException, BadPaddingException {
        String peticion = new String(decryptCipher.doFinal(decoder.decode(in.readUTF())));

        String respuesta = "Petición recibida: " + peticion;
        out.writeUTF(encoder.encodeToString(encryptCipher.doFinal(respuesta.getBytes(StandardCharsets.UTF_8))));
    }

}
