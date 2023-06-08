package swurg.gui.components.menus;

import java.awt.Color;
import java.util.Arrays;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.SwingUtilities;

import swurg.gui.components.tables.renderers.CustomTableCellRenderer;

public class ParametersContextMenu extends JPopupMenu {

  private JTable table;

  public ParametersContextMenu(JTable table) {
    this.table = table;

    initComponents();
  }

  private void initComponents() {
    JMenu highlightMenu = createHighlightMenu();
    this.add(highlightMenu);
  }

  private JMenu createHighlightMenu() {
    JMenu highlightMenu = new JMenu("Highlight");

    for (Color color : Arrays.asList(null, Color.RED, Color.ORANGE, Color.YELLOW, Color.GREEN, Color.BLUE,
        Color.MAGENTA, Color.PINK, Color.GRAY)) {
      JMenuItem menuItem = createHighlightMenuItem(color);

      highlightMenu.add(menuItem);
    }

    return highlightMenu;
  }

  private JMenuItem createHighlightMenuItem(Color color) {
    JMenuItem menuItem = new JMenuItem();

    menuItem.setOpaque(true);
    menuItem.setBackground(color);
    menuItem.setForeground(Color.BLACK);

    CustomTableCellRenderer renderer = (CustomTableCellRenderer) table.getDefaultRenderer(Object.class);

    menuItem.addActionListener(e -> {
      int[] selectedRows = table.getSelectedRows();

      // Set the highlight color for each selected row
      for (int row : selectedRows) {
        // Mapping view row to model row using a unique identifier
        Object rowId = table.getValueAt(row, table.getColumn("#").getModelIndex());

        SwingUtilities.invokeLater(() -> {
          renderer.setRowHighlightColor(rowId, color);
        });
      }
    });

    return menuItem;
  }
}
