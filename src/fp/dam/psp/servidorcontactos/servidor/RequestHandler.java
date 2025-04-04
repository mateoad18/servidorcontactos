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

            // Modificar este bloque de código para generar los cipher para cifrado
            // simétrico no algoritmo "AES/GCM/NoPadding".
            // Leer el vector de inicialización (iv) usado por el algoritmo "AES/GCM/NoPadding" en lugar del algoritmo (linea 56).
            // {{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{
            /*
            * Cifrar las petciones del cliente(el cliente manda al servidor las periciones que este debe de hacer y,
            *  el servidor debe de cifrar las peticiones y el propio contenido*/
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

            // }}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}

            procesarPeticion();
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error: " + e.getLocalizedMessage() + " : " +
                    socket.getInetAddress() + " : " + LocalDateTime.now());
        }
    }

    void procesarPeticion() throws IOException, IllegalBlockSizeException, BadPaddingException {
        String peticion = new String(decryptCipher.doFinal(decoder.decode(in.readUTF())));

        StringBuilder respuesta = new StringBuilder();
        respuesta.append("Petición recibida: ");
        respuesta.append(peticion);
        respuesta.append("\n");
        respuesta.append("Respuesta: hola cliente");

        out.writeUTF(encoder.encodeToString(encryptCipher.doFinal(respuesta.toString().getBytes(StandardCharsets.UTF_8))));
    }

}
