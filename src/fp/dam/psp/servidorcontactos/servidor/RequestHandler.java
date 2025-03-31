package fp.dam.psp.servidorcontactos.servidor;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
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

    public RequestHandler(Socket socket, X509Certificate certificate, PrivateKey privateKey) throws SocketException {
        this.socket = socket;
        this.certificate = certificate;
        this.privateKey = privateKey;
        socket.setSoTimeout(10000);
    }

    @Override
    public void run() {
        try (socket) {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Enviar el certificado del servidor codificado en Base64
            out.writeUTF(encoder.encodeToString(certificate.getEncoded()));

            // Crear un Cipher de cifrado asimétrico para descifrar la clave secreta que enviará el cliente
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Leer clave secreta cifrada enviada por el cliente y descifrarla
            byte[] encodedKey = cipher.doFinal(decoder.decode(in.readUTF()));
            String algorithm = in.readUTF();
            SecretKey key = new SecretKeySpec(encodedKey, algorithm);

            Cipher sCipher = Cipher.getInstance(algorithm);
            sendEncripted(sCipher, "hola", key, out);
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error: " + e.getLocalizedMessage() + " : " +
                    socket.getInetAddress() + " : " + LocalDateTime.now());
        }
    }

    void sendEncripted(Cipher cipher, String text, SecretKey key, DataOutputStream out) throws GeneralSecurityException, IOException {
        cipher.init(Cipher.ENCRYPT_MODE, key);
        out.writeUTF(encoder.encodeToString(cipher.doFinal(text.getBytes(StandardCharsets.UTF_8))));
    }
}
