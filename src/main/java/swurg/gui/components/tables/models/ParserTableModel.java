package swurg.gui.components.tables.models;

import java.util.ArrayList;
import java.util.List;

import javax.swing.table.AbstractTableModel;

import burp.api.montoya.http.message.requests.HttpRequest;
import lombok.Data;
import swurg.observers.ParserTableModelObserver;
import swurg.observers.ParametersPanelObserver;
import swurg.utilities.RequestWithMetadata;

@Data
public class ParserTableModel extends AbstractTableModel {

    private List<RequestWithMetadata> requestWithMetadatas;
    private String[] columnNames = { "#", "Method", "Server", "Path", "Parameters (COOKIE, URL)", "Description" };

    // Add a list to hold the observers
    private List<ParserTableModelObserver> observers = new ArrayList<>();
    private List<ParametersPanelObserver> parametersPanelObservers = new ArrayList<>();

    public ParserTableModel(List<RequestWithMetadata> requestWithMetadatas) {
        this.requestWithMetadatas = requestWithMetadatas;
    }

    public void addRow(RequestWithMetadata requestWithMetadata) {
        int rowCount = getRowCount();
        requestWithMetadatas.add(requestWithMetadata);
        fireTableRowsInserted(rowCount, rowCount);
        notifyObservers();
    }

    public void removeRow(int rowIndex) {
        requestWithMetadatas.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
        notifyObservers();
    }

    public void clear() {
        requestWithMetadatas.clear();
        fireTableDataChanged();
        notifyObservers();
    }

    // Add a method to register observers
    public void registerObserver(ParserTableModelObserver observer) {
        observers.add(observer);
    }

    // Add a method to unregister observers
    public void unregisterObserver(ParserTableModelObserver observer) {
        observers.remove(observer);
    }

    // Add a method to notify the observers
    private void notifyObservers() {
        for (ParserTableModelObserver observer : observers) {
            observer.onRequestWithMetadatasUpdate();
        }
        notifyParametersPanelObservers();
    }

    // Add methods to register, unregister, and notify ParametersPanel observers
    public void registerParametersPanelObserver(ParametersPanelObserver observer) {
        parametersPanelObservers.add(observer);
    }

    public void unregisterParametersPanelObserver(ParametersPanelObserver observer) {
        parametersPanelObservers.remove(observer);
    }

    private void notifyParametersPanelObservers() {
        for (ParametersPanelObserver observer : parametersPanelObservers) {
            observer.onRequestWithMetadatasUpdate();
        }
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
        if (column == 0)
            return Integer.class;

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
