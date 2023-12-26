package swurg.gui.components.tables.models;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.table.AbstractTableModel;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.http.MyHttpRequest;
import lombok.Data;
import swurg.observers.ParserTableModelObserver;
import swurg.observers.ParametersPanelObserver;

@Data
public class ParserTableModel extends AbstractTableModel {

    private final String[] columnNames = { "#", "Scheme", "Method", "Server", "Path", "Parameters (COOKIE, URL)",
            "Description" };
    private final List<MyHttpRequest> myHttpRequests;

    private final List<ParserTableModelObserver> observers = new ArrayList<>();
    private final List<ParametersPanelObserver> parametersPanelObservers = new ArrayList<>();

    public ParserTableModel(List<MyHttpRequest> myHttpRequests) {
        this.myHttpRequests = myHttpRequests;
    }

    public void addRow(MyHttpRequest myHttpRequest) {
        int rowCount = getRowCount();
        myHttpRequests.add(myHttpRequest);
        fireTableRowsInserted(rowCount, rowCount);
        notifyObservers();
    }

    public void removeRow(int rowIndex) {
        myHttpRequests.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
        notifyObservers();
    }

    public void clear() {
        myHttpRequests.clear();
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
        for (ParserTableModelObserver observer : observers)
            observer.onMyHttpRequestsUpdate();

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
        for (ParametersPanelObserver observer : parametersPanelObservers)
            observer.onMyHttpRequestsUpdate();
    }

    @Override
    public int getRowCount() {
        return myHttpRequests.size();
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
        MyHttpRequest myHttpRequest = myHttpRequests.get(row);

        switch (column) {
            case 0:
                return row;
            case 1:
                return myHttpRequest.getHttpRequest().httpService().secure() ? "HTTPS" : "HTTP";
            case 2:
                return myHttpRequest.getHttpRequest().method();
            case 3:
                return myHttpRequest.getHttpRequest().httpService().host();
            case 4:
                return myHttpRequest.getHttpRequest().path();
            case 5:
                return myHttpRequest.getHttpRequest().parameters()
                        .stream()
                        .filter(parameter -> parameter.type() == HttpParameterType.COOKIE
                                || parameter.type() == HttpParameterType.URL)
                        .map(ParsedHttpParameter::name)
                        .collect(Collectors.joining(", "));
            case 6:
                return myHttpRequest.getDescription() != null ? myHttpRequest.getDescription() : "N/A";
            default:
                throw new IllegalArgumentException("Invalid column index");
        }
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }
}
