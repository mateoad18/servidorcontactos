package fp.dam.psp.servidorcontactos.Swing;

import javax.swing.*;
import java.awt.*;


public class ClienteGUI extends JFrame {
    private JTextField nombreField;
    private JTextField telefonoField;
    private JTextArea consolaArea;
    private JButton btnAñadir, btnListar, btnBorrar;

    public ClienteGUI() {
        setTitle("Cliente de Contactos");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(600, 400);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        // Panel superior con campos de texto para nombre y teléfono
        JPanel inputPanel = new JPanel(new GridLayout(2, 2, 5, 5));
        inputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
        inputPanel.add(new JLabel("Nombre:"));
        nombreField = new JTextField();
        inputPanel.add(nombreField);
        inputPanel.add(new JLabel("Teléfono:"));
        telefonoField = new JTextField();
        inputPanel.add(telefonoField);
        add(inputPanel, BorderLayout.NORTH);

        // Área de consola
        consolaArea = new JTextArea();
        consolaArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(consolaArea);
        add(scrollPane, BorderLayout.CENTER);

        // Panel inferior con botones
        JPanel panelBotones = new JPanel(new FlowLayout());
        btnAñadir = new JButton("Añadir");
        btnListar = new JButton("Listar");
        btnBorrar = new JButton("Borrar");
        panelBotones.add(btnAñadir);
        panelBotones.add(btnListar);
        panelBotones.add(btnBorrar);
        add(panelBotones, BorderLayout.SOUTH);

        setVisible(true);
    }
    public static void main(String[] args) {
        SwingUtilities.invokeLater(ClienteGUI::new);
    }
}
