package swurg.gui.components;

import java.awt.Dimension;
import java.util.regex.PatternSyntaxException;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;

public class FilterPanel extends JPanel {
    private final JTextField filterTextField;
    private final TableRowSorter<?> tableRowSorter;

    public FilterPanel(JTextField filterTextField, TableRowSorter<?> tableRowSorter) {
        this.filterTextField = filterTextField;
        this.tableRowSorter = tableRowSorter;

        this.add(new JLabel("Filter (regular expression, case-sensitive):"));
        // Prevents JTextField from collapsing on resizes...
        this.filterTextField.setMinimumSize(new Dimension(this.filterTextField.getPreferredSize()));
        this.add(this.filterTextField);

        this.setUpFilterTextField();
    }

    private void setUpFilterTextField() {
        this.filterTextField.getDocument().addDocumentListener(new DocumentListener() {
            private void updateFilter() {
                String regex = filterTextField.getText();
                try {
                    tableRowSorter.setRowFilter(regex.isEmpty() ? null : RowFilter.regexFilter(regex));
                } catch (PatternSyntaxException e) {
                    // Display an error message if the regex pattern is invalid
                }
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                updateFilter();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                updateFilter();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                // No action needed
            }
        });
    }
}
