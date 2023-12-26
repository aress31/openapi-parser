package swurg.gui.components.tables.models;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.table.AbstractTableModel;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.http.MyHttpRequest;
import lombok.Data;
import swurg.observers.MyObserver;

@Data
public class ParserTableModel extends AbstractTableModel {

    private final String[] columnNames = { "#", "Scheme", "Method", "Server", "Path", "Parameters (COOKIE, URL)",
            "Description" };
    private final List<MyHttpRequest> myHttpRequests;

    private final List<MyObserver> observers = new ArrayList<>();

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

    public void registerObserver(MyObserver observer) {
        observers.add(observer);
    }

    private void notifyObservers() {
        observers.forEach(observer -> observer.onMyHttpRequestsUpdate());
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
