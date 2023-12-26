package swurg.gui.components.tables.models;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.event.TableModelEvent;
import javax.swing.table.AbstractTableModel;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.http.MyHttpRequest;
import lombok.Getter;
import swurg.observers.TableModelObserver;

public class ParserTableModel extends AbstractTableModel {

    private final String[] columnNames = { "#", "Scheme", "Method", "Server", "Path", "Parameters (COOKIE, URL)",
            "Description" };

    @Getter
    private final List<MyHttpRequest> myHttpRequests = new ArrayList<MyHttpRequest>();

    private final List<TableModelObserver> observers = new ArrayList<>();

    public void addRows(List<MyHttpRequest> myHttpRequests) {
        this.myHttpRequests.addAll(myHttpRequests);
        fireTableDataChanged();
        notifyObservers(TableModelEvent.INSERT);
    }

    public void removeRow(int index) {
        this.myHttpRequests.remove(index);
        fireTableRowsDeleted(index, index);
        notifyObservers(TableModelEvent.DELETE);
    }

    public void clear() {
        this.myHttpRequests.clear();
        fireTableDataChanged();
        notifyObservers(TableModelEvent.DELETE);
    }

    public void registerObserver(TableModelObserver observer) {
        this.observers.add(observer);
    }

    private void notifyObservers(int event) {
        this.observers.forEach(observer -> observer.onMyHttpRequestsUpdate(event, myHttpRequests));
    }

    @Override
    public int getRowCount() {
        return this.myHttpRequests.size();
    }

    @Override
    public int getColumnCount() {
        return this.columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return this.columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        if (column == 0)
            return Integer.class;

        return super.getColumnClass(column);
    }

    @Override
    public Object getValueAt(int row, int column) {
        MyHttpRequest myHttpRequest = this.myHttpRequests.get(row);

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
