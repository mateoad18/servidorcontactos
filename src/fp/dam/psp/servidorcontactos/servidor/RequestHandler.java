package fp.dam.psp.servidorcontactos.servidor;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;

public class RequestHandler implements Runnable {

    private final Socket socket;
    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    public RequestHandler(Socket socket, X509Certificate certificate, PrivateKey privateKey) throws SocketException {
        this.socket = socket;
        this.certificate = certificate;
        this.privateKey = privateKey;
        socket.setSoTimeout(10000);
    }

    @Override
    public void run() {
        try (socket) {
            Base64.Encoder encoder = Base64.getEncoder();
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeUTF(encoder.encodeToString(certificate.getEncoded()));
            while (true);
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error: " + e.getLocalizedMessage() + " : " +
                    socket.getInetAddress() + " : " + LocalDateTime.now());
        }
    }
}
