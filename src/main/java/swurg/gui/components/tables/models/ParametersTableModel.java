package swurg.gui.components.tables.models;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.swing.table.AbstractTableModel;

import burp.http.MyHttpParameter;
import burp.http.MyHttpRequest;
import lombok.Data;

@Data
public class ParametersTableModel extends AbstractTableModel {

    private Set<MyHttpParameter> httpParameters;
    private String[] columnNames = { "#", "Parameter", "Type (BODY, COOKIE, URL)",
            "Parsed Value (Example Value or Data type)", "Edited Value" };

    public ParametersTableModel(Set<MyHttpParameter> httpParameters) {
        this.httpParameters = httpParameters;
    }

    public static ParametersTableModel fromRequestWithMetadataList(List<MyHttpRequest> myHttpRequests) {
        Set<MyHttpParameter> httpParameters = new LinkedHashSet<>();

        myHttpRequests.forEach(myHttpRequest -> myHttpRequest.getHttpRequest().parameters()
                .forEach(myHttpParameter -> httpParameters
                        .add(MyHttpParameter.builder().httpParameter(myHttpParameter).build())));

        return new ParametersTableModel(httpParameters);
    }

    public void updateData(List<MyHttpRequest> myHttpRequests) {
        Set<MyHttpParameter> httpParameters = new LinkedHashSet<>();

        myHttpRequests.forEach(myHttpRequest -> myHttpRequest.getHttpRequest().parameters()
                .forEach(myHttpParameter -> httpParameters
                        .add(MyHttpParameter.builder().httpParameter(myHttpParameter).build())));

        this.httpParameters = httpParameters;
    }

    public void addRow(MyHttpParameter myHttpParameter) {
        int rowCount = getRowCount();
        httpParameters.add(myHttpParameter);
        fireTableRowsInserted(rowCount, rowCount);
    }

    public void removeRow(int rowIndex) {
        MyHttpParameter toRemove = getHttpParameterAt(rowIndex);
        httpParameters.remove(toRemove);
        fireTableRowsDeleted(rowIndex, rowIndex);
    }

    public MyHttpParameter getHttpParameterAt(int rowIndex) {
        return httpParameters.stream().skip(rowIndex).findFirst().orElse(null);
    }

    @Override
    public int getRowCount() {
        return httpParameters.size();
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
        MyHttpParameter myHttpParameter = getHttpParameterAt(row);

        switch (column) {
            case 0:
                return row;
            case 1:
                return myHttpParameter.getHttpParameter().name();
            case 2:
                return myHttpParameter.getHttpParameter().type().toString();
            case 3:
                return myHttpParameter.getHttpParameter().value();
            case 4:
                return myHttpParameter.getEditedValue();
            default:
                throw new IllegalArgumentException("Invalid column index");
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 4) {
            // Assuming you want to store the edited value as a String
            String editedValue = (String) aValue;

            if (editedValue != null && !editedValue.trim().isEmpty()) {
                MyHttpParameter myHttpParameter = getHttpParameterAt(rowIndex);
                if (myHttpParameter != null) {
                    myHttpParameter.setEditedValue(editedValue);

                    // Notify the table that the data has changed
                    fireTableCellUpdated(rowIndex, columnIndex);
                }
            }
        } else {
            throw new IllegalArgumentException("Invalid column index");
        }
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 4;
    }
}
