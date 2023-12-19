package swurg.gui.components.tables.renderers;

import java.awt.Color;
import java.awt.Component;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.UIManager;

public class CustomTableCellRenderer extends DefaultTableCellRenderer {

  private Map<Object, Color> rowHighlightColors = new HashMap<>();

  public void setRowHighlightColor(Object rowId, Color color) {
    rowHighlightColors.put(rowId, color);
  }

  public void clearRowHighlightColor(Object rowId) {
    int clearedRowIndex = (int) rowId;
    rowHighlightColors.remove(rowId);

    // Reindex row highlight colors
    Map<Object, Color> newRowHighlightColors = new HashMap<>();
    rowHighlightColors.forEach((currentRowId, color) -> {
      int currentRowIndex = (int) currentRowId;
      if (currentRowIndex > clearedRowIndex)
        currentRowIndex--;

      newRowHighlightColors.put(currentRowIndex, color);
    });

    rowHighlightColors = newRowHighlightColors;
  }

  public void clearAllRowHighlightColors() {
    rowHighlightColors.clear();
  }

  @Override
  public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
      int row, int column) {
    Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
    Object rowId = table.getValueAt(row, table.getColumn("#").getModelIndex());
    Color highlightColor = rowHighlightColors.get(rowId);
    Color alternateColor = UIManager.getLookAndFeelDefaults().getColor("Table.alternateRowColor");

    c.setForeground(table.getForeground());

    if (isSelected && highlightColor != null) {
      c.setForeground(Color.BLACK);
      c.setBackground(blendColors(table.getSelectionBackground(), highlightColor, 0.5f));
    } else if (isSelected)
      c.setBackground(table.getSelectionBackground());
    else if (highlightColor != null) {
      c.setForeground(Color.BLACK);
      c.setBackground(highlightColor);
    } else if (row % 2 != 0)
      c.setBackground(alternateColor);
    else
      c.setBackground(table.getBackground());

    return c;
  }

  private Color blendColors(Color color1, Color color2, float ratio) {
    float inverseRatio = 1.0f - ratio;
    int red = (int) (color1.getRed() * ratio + color2.getRed() * inverseRatio);
    int green = (int) (color1.getGreen() * ratio + color2.getGreen() * inverseRatio);
    int blue = (int) (color1.getBlue() * ratio + color2.getBlue() * inverseRatio);

    return new Color(red, green, blue);
  }

}
