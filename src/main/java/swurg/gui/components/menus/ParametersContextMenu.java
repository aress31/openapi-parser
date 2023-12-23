package swurg.gui.components.menus;

import java.awt.Color;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.stream.IntStream;

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

  private void processSelectedRows(Consumer<Integer> action) {
    IntStream.of(table.getSelectedRows())
        .forEach(row -> {
          int index = (int) table.getValueAt(row, table.getColumn("#").getModelIndex());
          action.accept(index);
        });
  }

  private JMenu createHighlightMenu() {
    JMenu highlightMenu = new JMenu("Highlight");

    Arrays.asList(null, Color.RED, Color.ORANGE, Color.YELLOW, Color.GREEN, Color.BLUE,
        Color.MAGENTA, Color.PINK, Color.GRAY)
        .forEach(color -> highlightMenu.add(createHighlightMenuItem(color)));

    return highlightMenu;
  }

  private JMenuItem createHighlightMenuItem(Color color) {
    JMenuItem menuItem = new JMenuItem();

    menuItem.setOpaque(true);
    menuItem.setBackground(color);
    menuItem.setForeground(Color.BLACK);

    CustomTableCellRenderer renderer = (CustomTableCellRenderer) table.getDefaultRenderer(Object.class);

    menuItem.addActionListener(e -> processSelectedRows(index -> {
      SwingUtilities.invokeLater(() -> {
        renderer.setRowHighlightColor(index, color);
      });
    }));

    return menuItem;
  }
}
