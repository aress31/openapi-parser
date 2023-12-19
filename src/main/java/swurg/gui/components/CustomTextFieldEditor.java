package swurg.gui.components;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.AbstractCellEditor;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.TableCellEditor;

// TO FIX: Need to press enter then escape to commit the edit
public class CustomTextFieldEditor extends AbstractCellEditor implements TableCellEditor, ActionListener {
    private static final long serialVersionUID = 1L;
    private JTextField textField;

    public CustomTextFieldEditor() {
        textField = new JTextField();
        textField.addActionListener(this);
        textField.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // Check if left button was clicked
                if (SwingUtilities.isLeftMouseButton(e))
                    textField.selectAll(); // Select all text when clicked
            }
        });
        textField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                // Commit the edit and stop editing when focus is lost
                fireEditingStopped();
            }
        });
    }

    @Override
    public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
        textField.setText((String) value);
        return textField;
    }

    @Override
    public Object getCellEditorValue() {
        return textField.getText();
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        // Commit the edit and stop editing when Enter is pressed
        fireEditingStopped();
    }
}
