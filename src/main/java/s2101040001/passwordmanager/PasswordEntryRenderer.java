package s2101040001.passwordmanager;

import java.awt.Component;
import java.util.Map;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;

class PasswordEntryRenderer extends DefaultListCellRenderer {
    private final Map<String, PasswordEntry> passwordMap;

    public PasswordEntryRenderer(Map<String, PasswordEntry> passwordMap) {
        this.passwordMap = passwordMap;
    }

    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
        super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

        String website = (String) value;
        PasswordEntry entry = passwordMap.get(website);

        if (entry != null) {
            setText(entry.getWebsite() + " (" + entry.getUsername() + ")");
        } else {
            setText(website); // Fallback just in case
        }

        return this;
    }
}
