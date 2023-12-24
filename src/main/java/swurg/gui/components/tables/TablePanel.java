package swurg.gui.components.tables;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import javax.swing.JFileChooser;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import lombok.Data;
import swurg.gui.components.FilterPanel;
import swurg.gui.components.tables.models.ParserTableModel;

@Data
public class TablePanel extends JPanel {

    private final TableModel tableModel;
    private final TableCellRenderer cellRenderer;
    private final HttpRequestEditor requestViewer;

    private JTable table;
    private TableRowSorter<TableModel> tableRowSorter;

    public TablePanel(TableModel tableModel, TableCellRenderer cellRenderer) {
        this(tableModel, cellRenderer, null);
    }

    public TablePanel(TableModel tableModel, TableCellRenderer cellRenderer, HttpRequestEditor requestViewer) {
        this.tableModel = tableModel;
        this.cellRenderer = cellRenderer;
        this.requestViewer = requestViewer;

        initComponents();
    }

    public void initComponents() {
        this.setLayout(new GridBagLayout());

        this.table = createTable(this.tableModel, this.cellRenderer, this.requestViewer);
        JScrollPane scrollPane = new JScrollPane(this.table);

        JPanel filterPanel = new FilterPanel(this.tableRowSorter);

        GridBagConstraints gbc = new GridBagConstraints();

        gbc.anchor = GridBagConstraints.NORTHWEST;
        this.add(filterPanel, gbc);

        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridy = 1;
        gbc.weightx = 1;
        gbc.weighty = 1;
        this.add(scrollPane, gbc);
    }

    private JTable createTable(TableModel tableModel, TableCellRenderer cellRenderer, HttpRequestEditor requestViewer) {
        JTable table = new JTable(tableModel) {
            @Override
            public void changeSelection(int row, int col, boolean toggle, boolean extend) {
                super.changeSelection(row, col, toggle, extend);

                if (requestViewer != null) {
                    int modelIndex = tableRowSorter.convertRowIndexToModel(row);
                    HttpRequest selectedHttpRequest = ((ParserTableModel) tableModel).getHttpRequestAt(modelIndex);

                    SwingUtilities.invokeLater(() -> {
                        requestViewer.setRequest(selectedHttpRequest);
                    });
                }
            }
        };

        table.setDefaultRenderer(Object.class, cellRenderer);
        table.setAutoCreateRowSorter(true);

        this.tableRowSorter = new TableRowSorter<>(table.getModel());
        table.setRowSorter(tableRowSorter);

        return table;
    }

    public void setContextMenu(JPopupMenu contextMenu) {
        if (table != null && contextMenu != null) {
            // Add "Export to CSV" menu item
            JMenuItem exportCsvMenuItem = new JMenuItem("Export to CSV");
            exportCsvMenuItem.addActionListener((ActionEvent e) -> {
                try {
                    exportTableToCsv();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            });
            contextMenu.add(new JSeparator());
            contextMenu.add(exportCsvMenuItem);

            table.addMouseListener(new TableMouseListener(contextMenu));
        }
    }

    private void exportTableToCsv() throws IOException {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Specify a file to save the CSV data");

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();

            // Ensure the file has a .csv extension
            String filePath = fileToSave.getAbsolutePath();
            if (!filePath.toLowerCase().endsWith(".csv")) {
                filePath += ".csv";
                fileToSave = new File(filePath);
            }

            try (FileWriter writer = new FileWriter(fileToSave)) {
                TableModel model = table.getModel();
                int columnCount = model.getColumnCount();

                // Write column headers
                for (int col = 0; col < columnCount; col++) {
                    writer.write(model.getColumnName(col));
                    if (col < columnCount - 1)
                        writer.write(",");
                }
                writer.write("\n");

                // Write table data for selected rows only
                int[] selectedRows = table.getSelectedRows();
                for (int viewRowIndex : selectedRows) {
                    int modelRowIndex = table.convertRowIndexToModel(viewRowIndex);
                    for (int col = 0; col < columnCount; col++) {
                        Object value = model.getValueAt(modelRowIndex, col);
                        writer.write(value != null ? value.toString() : "");
                        if (col < columnCount - 1)
                            writer.write(",");
                    }
                    writer.write("\n");
                }
            }
        }
    }

    private class TableMouseListener extends MouseAdapter {

        private JPopupMenu contextMenu;

        public TableMouseListener(JPopupMenu contextMenu) {
            this.contextMenu = contextMenu;
        }

        @Override
        public void mouseReleased(MouseEvent e) {
            handleContextMenuEvent(e);
        }

        @Override
        public void mousePressed(MouseEvent e) {
            handleContextMenuEvent(e);
        }

        private void handleContextMenuEvent(MouseEvent e) {
            if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
                int selectedRow = table.rowAtPoint(e.getPoint());

                if (selectedRow >= 0 && selectedRow < table.getRowCount()
                        && !table.getSelectionModel().isSelectedIndex(selectedRow))
                    table.setRowSelectionInterval(selectedRow, selectedRow);

                contextMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        }
    }
}
