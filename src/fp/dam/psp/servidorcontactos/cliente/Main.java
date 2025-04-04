package fp.dam.psp.servidorcontactos.cliente;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
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
            String b64Certificate = in.readUTF();
            byte[] certificateBytes = decoder.decode(b64Certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBytes));
            PublicKey publicKey = certificate.getPublicKey();
            System.out.println(certificate.getSubjectX500Principal().getName());
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

}
