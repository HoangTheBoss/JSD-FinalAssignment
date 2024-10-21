package s2101040001.passwordmanager;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class PasswordManager extends JFrame {
    private JTextField txtWebsite, txtUsername, txtPassword;
    private JList<String> passwordList;
    private DefaultListModel<String> listModel;
    private Map<String, PasswordEntry> passwordMap = new HashMap<>();
    private String storageFilePath = "passwords.enc"; // Path for the password file (USB)
    private SecretKeySpec masterKey;

    public PasswordManager(String masterPassword) {
        setTitle("Portable Password Manager");
        setSize(500, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(null);

        JLabel lblWebsite = new JLabel("Website URL:");
        lblWebsite.setBounds(20, 60, 200, 25);
        add(lblWebsite);

        txtWebsite = new JTextField();
        txtWebsite.setBounds(220, 60, 200, 25);
        add(txtWebsite);

        JLabel lblUsername = new JLabel("Username:");
        lblUsername.setBounds(20, 100, 100, 25);
        add(lblUsername);

        txtUsername = new JTextField();
        txtUsername.setBounds(150, 100, 200, 25);
        add(txtUsername);

        JLabel lblPassword = new JLabel("Password:");
        lblPassword.setBounds(20, 140, 100, 25);
        add(lblPassword);

        txtPassword = new JTextField();
        txtPassword.setBounds(150, 140, 200, 25);
        add(txtPassword);

        JButton btnAdd = new JButton("Add");
        btnAdd.setBounds(150, 180, 100, 25);
        add(btnAdd);

        listModel = new DefaultListModel<>();
        passwordList = new JList<>(listModel);
        passwordList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane listScrollPane = new JScrollPane(passwordList);
        listScrollPane.setBounds(20, 220, 440, 120);
        add(listScrollPane);

        btnAdd.addActionListener(e -> addPassword());

        // Add single-click and double-click actions to the list
        passwordList.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                int index = passwordList.locationToIndex(e.getPoint());
                if (index >= 0) {
                    String selectedWebsite = listModel.getElementAt(index);
                    PasswordEntry entry = passwordMap.get(selectedWebsite);
                    if (e.getClickCount() == 1) {
                        // Single-click: Show the dialog with username and password, and options to copy/open
                        showEntryDialog(entry);
                    }
                }
            }
        });

        // Derive the key from the master password
        try {
            this.masterKey = deriveKeyFromPassword(masterPassword);
            loadStoredPasswords(); // Load stored passwords if the master password is correct
            displayPasswords(); // Display passwords in the UI
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Incorrect master password.");
            throw new RuntimeException("Incorrect master password", e);
        }
    }

    private void showEntryDialog(PasswordEntry entry) {
        // Dialog with username and password, and options to copy username, copy password, open website
        JDialog dialog = new JDialog(this, "Password Entry", true);
        dialog.setLayout(new BorderLayout());
        dialog.setSize(300, 200);

        JTextArea infoArea = new JTextArea();
        infoArea.setEditable(false);
        infoArea.setText("Website: " + entry.getWebsite() + "\nUsername: " + entry.getUsername() + "\nPassword: " + entry.getPassword());
        dialog.add(infoArea, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        JButton btnCopyUsername = new JButton("Copy Username");
        JButton btnCopyPassword = new JButton("Copy Password");
        JButton btnOpenWebsite = new JButton("Open Website");

        buttonPanel.add(btnCopyUsername);
        buttonPanel.add(btnCopyPassword);
        buttonPanel.add(btnOpenWebsite);

        dialog.add(buttonPanel, BorderLayout.SOUTH);

        btnCopyUsername.addActionListener(e -> copyToClipboard(entry.getUsername()));
        btnCopyPassword.addActionListener(e -> copyToClipboard(entry.getPassword()));
        btnOpenWebsite.addActionListener(e -> openWebsite(entry.getWebsite()));

        dialog.setVisible(true);
    }

    private void copyToClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        JOptionPane.showMessageDialog(null, "Copied to clipboard!");
    }

    private void openWebsite(String website) {
        try {
            Desktop.getDesktop().browse(new URI(website));
        } catch (IOException | URISyntaxException e) {
            JOptionPane.showMessageDialog(this, "Failed to open website: " + website);
            e.printStackTrace();
        }
    }

    private void addPassword() {
        String website = txtWebsite.getText();
        String username = txtUsername.getText();
        String password = txtPassword.getText();

        // Validate the website URL
        if (!isValidUrl(website)) {
            JOptionPane.showMessageDialog(this, "Invalid URL. Please enter a valid URL starting with http or https.");
            return;
        }

        PasswordEntry entry = new PasswordEntry(website, username, password);
        passwordMap.put(website, entry);
        savePasswords();
        displayPasswords();

        txtWebsite.setText("");
        txtUsername.setText("");
        txtPassword.setText("");
    }

    private boolean isValidUrl(String url) {
        String regex = "^((https?|ftp|smtp):\\/\\/)?(www.)?[a-z0-9]+\\.[a-z]+(\\/[a-zA-Z0-9#]+\\/?)*$";
        return Pattern.matches(regex, url);
    }

    private void displayPasswords() {
        listModel.clear();
        for (String website : passwordMap.keySet()) {
            listModel.addElement(website); // Only display the website in the list
        }
    }

    private void savePasswords() {
        try {
            Gson gson = new Gson();
            String json = gson.toJson(passwordMap);
            byte[] encryptedData = encryptData(json.getBytes(), masterKey);
            Files.write(Paths.get(storageFilePath), encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void loadStoredPasswords() {
        try {
            if (!Files.exists(Paths.get(storageFilePath))) return;

            byte[] encryptedData = Files.readAllBytes(Paths.get(storageFilePath));
            byte[] decryptedData = decryptData(encryptedData, masterKey);
            String json = new String(decryptedData);
            Gson gson = new Gson();
            passwordMap = gson.fromJson(json, new TypeToken<Map<String, PasswordEntry>>(){}.getType());
        } catch (javax.crypto.BadPaddingException e) {
            throw new RuntimeException("Incorrect master password", e);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] encryptData(byte[] data, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private byte[] decryptData(byte[] encryptedData, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    private SecretKeySpec deriveKeyFromPassword(String password) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = password.getBytes("UTF-8");
        key = sha.digest(key);
        return new SecretKeySpec(Arrays.copyOf(key, 16), "AES");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            boolean isNew = !Files.exists(Paths.get("passwords.enc")); // Check if the file exists
            int attempts = 0;
            final int MAX_RETRIES = 3;

            while (attempts < MAX_RETRIES) {  // Retry loop with a maximum number of tries
                String masterPassword = promptMasterPassword(isNew);

                if (masterPassword != null) {
                    try {
                        new PasswordManager(masterPassword).setVisible(true);
                        break;  // Exit the loop if the master password is correct
                    } catch (RuntimeException e) {
                        attempts++;
                        JOptionPane.showMessageDialog(null, "Incorrect master password. Attempts remaining: " + (MAX_RETRIES - attempts));
                    }
                } else {
                    System.exit(0); // Exit if user cancels the prompt
                }
            }
            if (attempts >= MAX_RETRIES) {
                JOptionPane.showMessageDialog(null, "Too many incorrect attempts. Exiting.");
                System.exit(0);  // Exit after max retries
            }
        });
    }

    // Prompt dialog for master password
    private static String promptMasterPassword(boolean isNew) {
        JPasswordField pwdField = new JPasswordField();
        Object[] message = {
                isNew ? "Create a new Master Password:" : "Enter Master Password:", pwdField
        };

        int option = JOptionPane.showConfirmDialog(null, message, isNew ? "Create Master Password" : "Master Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (option == JOptionPane.OK_OPTION) {
            return new String(pwdField.getPassword());
        } else {
            System.exit(0); // Exit if user cancels the prompt
            return null;
        }
    }
}

class PasswordEntry {
    private String website;
    private String username;
    private String password;

    public PasswordEntry(String website, String username, String password) {
        this.website = website;
        this.username = username;
        this.password = password;
    }

    public String getWebsite() {
        return website;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
