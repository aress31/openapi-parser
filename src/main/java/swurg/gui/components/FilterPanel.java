package swurg.gui.components;

import java.awt.Dimension;
import java.util.regex.PatternSyntaxException;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;

public class FilterPanel extends JPanel {

    private final TableRowSorter<?> tableRowSorter;

    private final JLabel eastLabel = new JLabel("0 hits");
    private final JTextField filterTextField = new JTextField(32);

    public FilterPanel(TableRowSorter<?> tableRowSorter) {
        this.tableRowSorter = tableRowSorter;

        initComponents();

        addFilterTextFieldListener();
    }

    public void initComponents() {
        JLabel westLabel = new JLabel("Filter (regex, case-sensitive):");

        // Ensures JTextField size stability during resizing...
        this.filterTextField.setMinimumSize(new Dimension(this.filterTextField.getPreferredSize()));

        this.add(westLabel);
        this.add(this.filterTextField);
        this.add(this.eastLabel);
    }

    private void addFilterTextFieldListener() {
        this.filterTextField.getDocument().addDocumentListener(new DocumentListener() {
            private void updateFilter() {
                SwingUtilities.invokeLater(() -> {
                    String regex = filterTextField.getText();

                    try {
                        if (regex.isBlank()) {
                            tableRowSorter.setRowFilter(null);
                            eastLabel.setText("0 hits");
                        } else {
                            tableRowSorter.setRowFilter(RowFilter.regexFilter(regex));

                            int rowCount = tableRowSorter.getViewRowCount();
                            eastLabel.setText(String.format("%d hit%s", rowCount, (rowCount != 1 ? "s" : "")));
                        }
                    } catch (PatternSyntaxException e) {
                        // Show an error message if the regex pattern is invalid.
                    }
                });
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
                // TODO Auto-generated method stub
            }
        });
    }
}
