package fp.dam.psp.servidorcontactos.servidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(
                ClassLoader.getSystemResourceAsStream("/keystore"),
                "practicas".toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("servidor");
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("servidor", "claveprivada".toCharArray());
        ExecutorService service = Executors.newFixedThreadPool(50);
        ServerSocket serverSocket = new ServerSocket(9000);
        System.out.println("Servidor de contactos escuchando en puerto 9000");
        while (true) {
            service.submit(new RequestHandler(serverSocket.accept(), certificate, privateKey));
        }
    }

}
