package s2101040001.passwordmanager;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;

public class PasswordManager extends JFrame {
    private JTextField txtWebsite, txtUsername, txtPassword;
    private JList<String> passwordList;
    private DefaultListModel<String> listModel;
    private Map<String, PasswordEntry> passwordMap = new HashMap<>();
    private final String storageFilePath = "passwords.enc";
    private SecretKeySpec masterKey;

    public PasswordManager(String masterPassword) {
        setTitle("Portable Password Manager");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Create tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();

        // Password Management Tab
        JPanel passwordManagerPanel = createPasswordManagerPanel();
        tabbedPane.addTab("Manage Passwords", passwordManagerPanel);

        // Settings Tab
        JPanel settingsPanel = createSettingsPanel();
        tabbedPane.addTab("Settings", settingsPanel);

        add(tabbedPane, BorderLayout.CENTER);

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

    private JPanel createPasswordManagerPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Top panel for form input
        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Website field
        gbc.gridx = 0;
        gbc.gridy = 0;
        inputPanel.add(new JLabel("Website URL:"), gbc);

        txtWebsite = new JTextField(20);
        gbc.gridx = 1;
        inputPanel.add(txtWebsite, gbc);

        // Username field
        gbc.gridx = 0;
        gbc.gridy = 1;
        inputPanel.add(new JLabel("Username:"), gbc);

        txtUsername = new JTextField(20);
        gbc.gridx = 1;
        inputPanel.add(txtUsername, gbc);

        // Password field
        gbc.gridx = 0;
        gbc.gridy = 2;
        inputPanel.add(new JLabel("Password:"), gbc);

        txtPassword = new JTextField(20);
        gbc.gridx = 1;
        inputPanel.add(txtPassword, gbc);

        // Add button
        JButton btnAdd = new JButton("Add");
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        btnAdd.addActionListener(e -> addPassword());
        inputPanel.add(btnAdd, gbc);

        // Search field
        gbc.gridx = 0;
        gbc.gridy = 4;
        inputPanel.add(new JLabel("Search:"), gbc);

        JTextField txtSearch = new JTextField(20);
        gbc.gridx = 1;
        inputPanel.add(txtSearch, gbc);

        // Add search functionality
        txtSearch.addCaretListener(e -> filterPasswords(txtSearch.getText()));

        panel.add(inputPanel, BorderLayout.NORTH);

        // List for displaying passwords
        listModel = new DefaultListModel<>();
        passwordList = new JList<>(listModel);
        passwordList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Create and pass the passwordMap to the renderer
        PasswordEntryRenderer renderer = new PasswordEntryRenderer(passwordMap);
        passwordList.setCellRenderer(renderer);

        JScrollPane listScrollPane = new JScrollPane(passwordList);
        panel.add(listScrollPane, BorderLayout.CENTER);

        passwordList.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                int index = passwordList.locationToIndex(e.getPoint());
                if (index >= 0) {
                    String selectedWebsite = listModel.getElementAt(index);
                    PasswordEntry entry = passwordMap.get(selectedWebsite);
                    if (e.getClickCount() == 1) {
                        showEntryDialog(entry);
                    }
                }
            }
        });

        return panel;
    }

    private void filterPasswords(String query) {
        listModel.clear();
        for (String website : passwordMap.keySet()) {
            if (website.toLowerCase().contains(query.toLowerCase())) {
                listModel.addElement(website);
            }
        }
    }


    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel();
        JButton btnChangePassword = new JButton("Change Master Password");
        btnChangePassword.addActionListener(e -> changeMasterPassword());
        panel.add(btnChangePassword);
        return panel;
    }

    private void changeMasterPassword() {
        // Prompt for current password
        String currentPassword = promptForCurrentPassword();
        if (currentPassword == null) return; // User cancelled

        // Verify the current password
        try {
            SecretKeySpec currentKey = deriveKeyFromPassword(currentPassword);
            // Test decryption of existing passwords
            loadStoredPasswords(currentKey);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Current password is incorrect.");
            return;
        }

        // Prompt for new password
        String newPassword = JOptionPane.showInputDialog(this, "Enter new master password:");
        if (newPassword != null && !newPassword.isEmpty()) {
            try {
                // Update master key and save passwords
                this.masterKey = deriveKeyFromPassword(newPassword);
                savePasswords(); // Re-encrypt with new key
                JOptionPane.showMessageDialog(this, "Master password changed successfully.");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Failed to change master password.");
                e.printStackTrace();
            }
        }
    }

    private String promptForCurrentPassword() {
        JPasswordField pwdField = new JPasswordField();
        Object[] message = {
                "Enter current Master Password:", pwdField
        };

        int option = JOptionPane.showConfirmDialog(null, message, "Current Master Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (option == JOptionPane.OK_OPTION) {
            return new String(pwdField.getPassword());
        }
        return null; // User cancelled
    }

    private void loadStoredPasswords(SecretKeySpec key) {
        try {
            if (!Files.exists(Paths.get(storageFilePath))) return;

            byte[] encryptedData = Files.readAllBytes(Paths.get(storageFilePath));
            byte[] decryptedData = decryptData(encryptedData, key);
            String json = new String(decryptedData);
            Gson gson = new Gson();
            passwordMap = gson.fromJson(json, new TypeToken<Map<String, PasswordEntry>>(){}.getType());
        } catch (javax.crypto.BadPaddingException e) {
            throw new RuntimeException("Incorrect current master password", e);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void showEntryDialog(PasswordEntry entry) {
        JDialog dialog = new JDialog(this, "Password Entry", true);
        dialog.setLayout(new BorderLayout());
        dialog.setSize(400, 300);

        // Panel for entry details
        JPanel detailsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Website (Non-editable)
        gbc.gridx = 0;
        gbc.gridy = 0;
        detailsPanel.add(new JLabel("Website:"), gbc);

        JTextField txtWebsiteDisplay = new JTextField(entry.getWebsite());
        txtWebsiteDisplay.setEditable(false);
        gbc.gridx = 1;
        detailsPanel.add(txtWebsiteDisplay, gbc);

        // Username (Editable in Edit Mode)
        gbc.gridx = 0;
        gbc.gridy = 1;
        detailsPanel.add(new JLabel("Username:"), gbc);

        JTextField txtUsernameDisplay = new JTextField(entry.getUsername());
        txtUsernameDisplay.setEditable(false);
        gbc.gridx = 1;
        detailsPanel.add(txtUsernameDisplay, gbc);

        // Password (Hidden initially with toggle button)
        gbc.gridx = 0;
        gbc.gridy = 2;
        detailsPanel.add(new JLabel("Password:"), gbc);

        JPasswordField txtPasswordDisplay = new JPasswordField(entry.getPassword());
        txtPasswordDisplay.setEditable(false);
        txtPasswordDisplay.setEchoChar('*');  // Mask password

        JButton btnShowPassword = new JButton("Show Password");
        btnShowPassword.addActionListener(e -> {
            if (txtPasswordDisplay.getEchoChar() == '*') {
                txtPasswordDisplay.setEchoChar((char) 0); // Show password
                btnShowPassword.setText("Hide Password");
            } else {
                txtPasswordDisplay.setEchoChar('*'); // Hide password
                btnShowPassword.setText("Show Password");
            }
        });

        gbc.gridx = 1;
        detailsPanel.add(txtPasswordDisplay, gbc);

        gbc.gridy = 3;
        detailsPanel.add(btnShowPassword, gbc);

        dialog.add(detailsPanel, BorderLayout.CENTER);

        // Action buttons panel
        JPanel buttonPanel = new JPanel(new GridLayout(2, 1)); // 2 rows for the button panel

        // Upper row with 3 buttons (FlowLayout)
        JPanel upperButtonPanel = new JPanel(new FlowLayout());
        JButton btnCopyUsername = new JButton("Copy Username");
        JButton btnCopyPassword = new JButton("Copy Password");
        JButton btnOpenWebsite = new JButton("Open Website");

        upperButtonPanel.add(btnCopyUsername);
        upperButtonPanel.add(btnCopyPassword);
        upperButtonPanel.add(btnOpenWebsite);
        buttonPanel.add(upperButtonPanel); // Add upper panel to button panel

        // Lower row with 2 buttons (FlowLayout)
        JPanel lowerButtonPanel = new JPanel(new FlowLayout()); // Changed to FlowLayout
        JButton btnEdit = new JButton("Edit");
        JButton btnDelete = new JButton("Delete");

        lowerButtonPanel.add(btnEdit);
        lowerButtonPanel.add(btnDelete);
        buttonPanel.add(lowerButtonPanel); // Add lower panel to button panel

        dialog.add(buttonPanel, BorderLayout.SOUTH);

        // Copy actions
        btnCopyUsername.addActionListener(e -> copyToClipboard(entry.getUsername()));
        btnCopyPassword.addActionListener(e -> copyToClipboard(entry.getPassword()));

        // Open website action
        btnOpenWebsite.addActionListener(e -> openWebsite(entry.getWebsite()));

        // Edit mode toggle
        btnEdit.addActionListener(e -> {
            if (btnEdit.getText().equals("Edit")) {
                txtUsernameDisplay.setEditable(true);
                txtPasswordDisplay.setEditable(true);
                btnEdit.setText("Save");
            } else {
                // Save the edited data
                entry.setUsername(txtUsernameDisplay.getText());
                entry.setPassword(new String(txtPasswordDisplay.getPassword()));
                passwordMap.put(entry.getWebsite(), entry);  // Update the entry in the map
                savePasswords();  // Save the changes to storage
                txtUsernameDisplay.setEditable(false);
                txtPasswordDisplay.setEditable(false);
                btnEdit.setText("Edit");
                JOptionPane.showMessageDialog(dialog, "Changes saved successfully.");
            }
        });

        // Delete action
        btnDelete.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(dialog, "Are you sure you want to delete this entry?", "Confirm Delete", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                passwordMap.remove(entry.getWebsite());
                savePasswords();  // Save changes after deletion
                displayPasswords();  // Refresh the list display
                dialog.dispose();  // Close the dialog
            }
        });

        // Adjust dialog size and make it visible
        dialog.pack();
        dialog.setLocationRelativeTo(this);
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
        byte[] key = password.getBytes(StandardCharsets.UTF_8);
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
