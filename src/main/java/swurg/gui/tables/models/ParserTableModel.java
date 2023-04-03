package swurg.gui.tables.models;

import java.util.List;

import javax.swing.table.AbstractTableModel;

import burp.api.montoya.http.message.requests.HttpRequest;
import swurg.utilities.RequestWithMetadata;

public class ParserTableModel extends AbstractTableModel {

    private List<RequestWithMetadata> requestWithMetadatas;
    private String[] columnNames = { "#", "Method", "Server", "Path", "Parameters (COOKIE, URL)", "Description" };

    public ParserTableModel(List<RequestWithMetadata> requestWithMetadatas) {
        this.requestWithMetadatas = requestWithMetadatas;
    }

    public void addRow(RequestWithMetadata logEntry) {
        int rowCount = getRowCount();
        requestWithMetadatas.add(logEntry);
        fireTableRowsInserted(rowCount, rowCount);
    }

    public void removeRow(int rowIndex) {
        requestWithMetadatas.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
    }

    public void clear() {
        requestWithMetadatas.clear();
        fireTableDataChanged();
    }

    public HttpRequest getHttpRequestAt(int rowIndex) {
        return requestWithMetadatas.get(rowIndex).getHttpRequest();
    }

    @Override
    public int getRowCount() {
        return requestWithMetadatas.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        if (column == 0) {
            return Integer.class;
        }
        return super.getColumnClass(column);
    }

    @Override
    public Object getValueAt(int row, int column) {
        RequestWithMetadata requestWithMetadata = requestWithMetadatas.get(row);

        switch (column) {
            case 0:
                return row;
            case 1:
                return requestWithMetadata.getHttpRequest().method();
            case 2:
                return requestWithMetadata.getHttpRequest().httpService().host();
            case 3:
                return requestWithMetadata.getHttpRequest().path();
            case 4:
                return requestWithMetadata.getParameters();
            case 5:
                return requestWithMetadata.getDescription() != null ? requestWithMetadata.getDescription() : "N/A";
            default:
                throw new IllegalArgumentException("Invalid column index");
        }
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }
}
