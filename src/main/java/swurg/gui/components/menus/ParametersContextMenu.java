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

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.ui.swing.SwingUtils;
import swurg.gui.components.tables.renderers.CustomTableCellRenderer;

public class ParametersContextMenu extends JPopupMenu {

  private final SwingUtils swingUtils;

  private final JTable table;

  public ParametersContextMenu(MontoyaApi montoyaApi, JTable table) {
    this.swingUtils = montoyaApi.userInterface().swingUtils();

    this.table = table;

    initComponents();
  }

  private void initComponents() {
    this.add(createHighlightMenu());
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

    Arrays.stream(HighlightColor.values())
        .forEach(highlightColor -> {
          Color color = (highlightColor.compareTo(HighlightColor.NONE) == 0) ? null
              : this.swingUtils.colorForHighLight(highlightColor);
          highlightMenu.add(createHighlightMenuItem(color));
        });

    return highlightMenu;
  }

  private JMenuItem createHighlightMenuItem(Color color) {
    JMenuItem menuItem = new JMenuItem();

    menuItem.setOpaque(true);
    menuItem.setBackground(color);
    menuItem.setForeground(Color.BLACK);

    CustomTableCellRenderer renderer = (CustomTableCellRenderer) table.getDefaultRenderer(Object.class);

    menuItem.addActionListener(e -> processSelectedRows(index -> {
      SwingUtilities.invokeLater(() -> renderer.setRowHighlightColor(index, color));
    }));

    return menuItem;
  }
}
