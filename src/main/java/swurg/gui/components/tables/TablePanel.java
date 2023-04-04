package swurg.gui.components.tables;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
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

    private JTable table;
    private TableRowSorter<TableModel> tableRowSorter;
    private JTextField filterTextField;

    public TablePanel(TableModel tableModel, TableCellRenderer cellRenderer) {
        this(tableModel, cellRenderer, null);
    }

    public TablePanel(TableModel tableModel, TableCellRenderer cellRenderer, HttpRequestEditor requestViewer) {
        this.setLayout(new GridBagLayout());

        filterTextField = new JTextField(32);
        table = createTable(tableModel, cellRenderer, requestViewer);

        JPanel filterPanel = new FilterPanel(filterTextField, tableRowSorter);
        JScrollPane scrollPane = new JScrollPane(table);

        GridBagConstraints filterPanelConstraints = new GridBagConstraints();
        filterPanelConstraints.gridx = 0;
        filterPanelConstraints.gridy = 0;
        filterPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        this.add(filterPanel, filterPanelConstraints);

        GridBagConstraints tableConstraints = new GridBagConstraints();
        tableConstraints.gridx = 0;
        tableConstraints.gridy = 1;
        tableConstraints.fill = GridBagConstraints.BOTH;
        tableConstraints.weightx = 1.0;
        tableConstraints.weighty = 1.0;
        this.add(scrollPane, tableConstraints);
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

        tableRowSorter = new TableRowSorter<>(table.getModel());
        table.setRowSorter(tableRowSorter);

        return table;
    }

    public void setContextMenu(JPopupMenu contextMenu) {
        if (table != null && contextMenu != null) {
            table.addMouseListener(new TableMouseListener(contextMenu));
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

        private void handleContextMenuEvent(MouseEvent e) {
            if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
                int selectedRow = table.rowAtPoint(e.getPoint());

                if (selectedRow >= 0 && selectedRow < table.getRowCount()
                        && !table.getSelectionModel().isSelectedIndex(selectedRow)) {
                    table.setRowSelectionInterval(selectedRow, selectedRow);
                }

                contextMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        }
    }
}