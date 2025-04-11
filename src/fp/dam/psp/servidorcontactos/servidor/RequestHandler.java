package fp.dam.psp.servidorcontactos.servidor;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
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
import java.util.ArrayList;
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

    // ArrayList para almacenar los contactos
    private ArrayList<Contacto> contactos;

    public RequestHandler(Socket socket, X509Certificate certificate, PrivateKey privateKey, ArrayList<Contacto> contactos) throws IOException {
        this.socket = socket;
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.contactos = contactos;
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
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Leer clave secreta cifrada enviada por el cliente, decodificar B64 y descifrarla
            byte[] encodedKey = cipher.doFinal(decoder.decode(in.readUTF()));
            byte[] iv = Base64.getDecoder().decode(in.readUTF());

            // Decodificarla como un objeto SecretKey
            SecretKey key = new SecretKeySpec(encodedKey, "AES");

            // Crear los Cipher para cifrar y descifrar con la clave secreta
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, spec);
            decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, spec);

            // Procesar la petición
            procesarPeticion();
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error: " + e.getLocalizedMessage() + " : " +
                    socket.getInetAddress() + " : " + LocalDateTime.now());
        }
    }

    void procesarPeticion() throws IOException, IllegalBlockSizeException, BadPaddingException {
        // Leer la petición cifrada, decodificarla y descifrarla
        String peticion = new String(decryptCipher.doFinal(decoder.decode(in.readUTF())));

        // Procesar la petición
        String respuesta = tratarPeticion(peticion);

        // Cifrar la respuesta y enviarla de vuelta al cliente
        out.writeUTF(encoder.encodeToString(encryptCipher.doFinal(respuesta.getBytes(StandardCharsets.UTF_8))));
    }

    private String tratarPeticion(String cadena) {
        String salida = "";
        if (!cadena.contains(":") && !cadena.equals("listar")) {
            salida = "Error: el comando debe estar como se especifica";
        } else {
            String[] trozos = cadena.split(":");

            switch (trozos[0]) {
                case "listar":
                    salida = mostrarContactos();
                    break;
                case "buscar":
                    salida = buscarContacto(trozos[1]);
                    break;
                case "eliminar":
                    salida = eliminarContacto(trozos[1]);
                    break;
                case "añadir":
                    if (trozos.length == 3) {
                        salida = añadirContacto(trozos[1], Integer.parseInt(trozos[2]));
                    } else {
                        salida = "Faltan datos"; // Error por parámetros incorrectos
                    }
                    break;
                default:
                    salida = "Comando incorrecto"; // Comando no reconocido
                    break;
            }
        }
        return salida;
    }

    private String añadirContacto(String nombre, int telefono) {
        for (Contacto contacto : contactos) {
            if (contacto.getNombre().equals(nombre)) {
                return "Contacto repetido"; // Contacto ya existente
            }
        }
        contactos.add(new Contacto(nombre, telefono));
        return "Contacto añadido correctamente";
    }

    private String eliminarContacto(String nombre) {
        for (int i = 0; i < contactos.size(); i++) {
            if (contactos.get(i).getNombre().equals(nombre)) {
                contactos.remove(i);
                return "Borrado correctamente";
            }
        }
        return "No se ha podido eliminar, contacto no encontrado";
    }

    private String buscarContacto(String nombre) {
        for (Contacto contacto : contactos) {
            if (contacto.getNombre().equals(nombre)) {
                return "OK:" + contacto.toString();
            }
        }
        return "No existe el contacto";
    }

    private String mostrarContactos() {
        if (contactos.isEmpty()) {
            return "No hay contactos disponibles.";
        }

        StringBuilder cadena = new StringBuilder("Lista de contactos:");
        for (Contacto contacto : contactos) {
            cadena.append("\n").append(contacto.toString());
        }
        return cadena.toString();
    }
}