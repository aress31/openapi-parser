package swurg.gui.components.tables.models;

import java.util.LinkedHashSet;
import java.util.Set;

import javax.swing.table.AbstractTableModel;

import burp.http.MyHttpParameter;
import lombok.Getter;
import lombok.Setter;

public class ParametersTableModel extends AbstractTableModel {

    private final String[] columnNames = { "#", "Parameter", "Type (BODY, COOKIE, URL)",
            "Parsed Value (Example Value or Data type)", "Edited Value" };

    @Getter
    @Setter
    private Set<MyHttpParameter> myHttpParameters;

    public ParametersTableModel() {
        this.myHttpParameters = new LinkedHashSet<MyHttpParameter>();
    }

    public MyHttpParameter getHttpParameterAt(int rowIndex) {
        return this.myHttpParameters.stream().skip(rowIndex).findFirst().orElse(null);
    }

    @Override
    public int getRowCount() {
        return this.myHttpParameters.size();
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
            String editedValue = aValue.toString();

            if (!editedValue.isBlank()) {
                MyHttpParameter myHttpParameter = getHttpParameterAt(rowIndex);
                myHttpParameter.setEditedValue(editedValue);
                // Notify the table that the data has changed.
                fireTableCellUpdated(rowIndex, columnIndex);
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
