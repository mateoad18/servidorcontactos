package fp.dam.psp.servidorcontactos.servidor;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
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
        //socket.setSoTimeout(10000);
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());
    }

    @Override
    public void run() {
        try (socket) {
            // Enviar el certificado del servidor codificado en Base64
            out.writeUTF(encoder.encodeToString(certificate.getEncoded()));

            // Recibir clave secreta cifrada y IV
            byte[] encryptedKey = Base64.getDecoder().decode(in.readUTF());
            byte[] iv = Base64.getDecoder().decode(in.readUTF());

            // Descifrar clave secreta
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decodedKey = cipher.doFinal(encryptedKey);

            // Reconstruir clave secreta
            SecretKey key = new SecretKeySpec(decodedKey, "AES");

            // Configurar Ciphers AES/GCM
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, spec);
            decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, spec);

            // Procesar petición
            procesarPeticion();
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error: " + e.getLocalizedMessage() + " : " +
                    socket.getInetAddress() + " : " + LocalDateTime.now());
        }
    }

    public static SecretKey getKeyFromPassword(String password, byte[] salt) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    void procesarPeticion() {
        try {
            String peticion = new String(decryptCipher.doFinal(decoder.decode(in.readUTF())));
            String respuesta = tratarPeticion(peticion);
            out.writeUTF(encoder.encodeToString(encryptCipher.doFinal(respuesta.getBytes(StandardCharsets.UTF_8))));
        } catch (Exception e) {
            System.err.println("Error al procesar la petición: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String tratarPeticion(String cadena) {
        String salida;

        if (cadena.equals("listar")) {
            salida = mostrarContactos();
        } else if (cadena.startsWith("buscar:")) {
            String nombre = cadena.substring("buscar:".length());
            salida = buscarContacto(nombre);
        } else if (cadena.startsWith("eliminar:")) {
            String nombre = cadena.substring("eliminar:".length());
            salida = eliminarContacto(nombre);
        } else if (cadena.startsWith("añadir:")) {
            // obtener la parte después de "añadir:"
            String resto = cadena.substring("añadir:".length());

            // buscar el último ":" para separar nombre y teléfono (por si el nombre contiene ':')
            int indexUltimoDosPuntos = resto.lastIndexOf(":");
            if (indexUltimoDosPuntos == -1) {
                salida = "Error: formato incorrecto para añadir";
            } else {
                String nombre = resto.substring(0, indexUltimoDosPuntos);
                String telefonoStr = resto.substring(indexUltimoDosPuntos + 1);
                try {
                    int telefono = Integer.parseInt(telefonoStr);
                    salida = añadirContacto(nombre, telefono);
                } catch (NumberFormatException e) {
                    salida = "Error: el número de teléfono no es válido";
                }
            }
        } else {
            salida = "Comando incorrecto o mal formado";
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