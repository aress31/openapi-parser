package swurg.gui.components.tables.models;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.swing.table.AbstractTableModel;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.http.MyHttpParameter;
import lombok.Data;
import swurg.utilities.RequestWithMetadata;

@Data
public class ParametersTableModel extends AbstractTableModel {

    private Set<MyHttpParameter> httpParameters;
    private String[] columnNames = { "#", "Parameter", "Type (BODY, COOKIE, URL)",
            "Parsed Value (Data type or Example Value)", "Edited Value" };

    public ParametersTableModel(Set<MyHttpParameter> httpParameters) {
        this.httpParameters = httpParameters;
    }

    public static ParametersTableModel fromRequestWithMetadataList(List<RequestWithMetadata> requestWithMetadatas) {
        Set<MyHttpParameter> httpParameters = new LinkedHashSet<>();

        for (RequestWithMetadata requestWithMetadata : requestWithMetadatas) {
            for (HttpParameter httpParameter : requestWithMetadata.getHttpRequest().parameters()) {
                httpParameters.add(new MyHttpParameter(httpParameter));
            }
        }

        return new ParametersTableModel(httpParameters);
    }

    public void updateData(List<RequestWithMetadata> requestWithMetadatas) {
        Set<MyHttpParameter> httpParameters = new LinkedHashSet<>();

        for (RequestWithMetadata requestWithMetadata : requestWithMetadatas) {
            for (HttpParameter httpParameter : requestWithMetadata.getHttpRequest().parameters()) {
                httpParameters.add(new MyHttpParameter(httpParameter));
            }
        }

        this.httpParameters = httpParameters;
    }

    public void addRow(MyHttpParameter httpParameter) {
        int rowCount = getRowCount();
        httpParameters.add(httpParameter);
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
        if (column == 0) {
            return Integer.class;
        }
        return super.getColumnClass(column);
    }

    @Override
    public Object getValueAt(int row, int column) {
        MyHttpParameter httpParameter = getHttpParameterAt(row);

        switch (column) {
            case 0:
                return row;
            case 1:
                return httpParameter.name();
            case 2:
                return httpParameter.type().toString();
            case 3:
                return httpParameter.value();
            case 4:
                return httpParameter.getEditedValue();
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
                MyHttpParameter httpParameter = getHttpParameterAt(rowIndex);
                if (httpParameter != null) {
                    httpParameter.setEditedValue(editedValue);

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
