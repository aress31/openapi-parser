package swurg.gui.components.menus;

import java.awt.Color;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.SwingUtilities;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import swurg.gui.components.tables.models.ParserTableModel;
import swurg.gui.components.tables.renderers.CustomTableCellRenderer;

public class ParserContextMenu extends JPopupMenu {

  private MontoyaApi montoyaApi;
  private JTable table;

  public ParserContextMenu(MontoyaApi montoyaApi, JTable table) {
    this.montoyaApi = montoyaApi;
    this.table = table;

    initComponents();
  }

  private void initComponents() {
    JMenuItem copyToClipboard = createCopyToClipboardMenuItem();

    JMenuItem addToScope = createAddToScopeMenuItem();
    JMenuItem addToSiteMap = createAddToSiteMapMenuItem();
    JMenuItem activeScan = createActiveScanMenuItem();
    JMenuItem sendToIntruder = createSendToIntruderMenuItem();
    JMenuItem sendToRepeater = createSendToRepeaterMenuItem();
    JMenuItem sendToComparer = createSendToComparerMenuItem();
    JMenu highlightMenu = createHighlightMenu();
    JMenuItem clearItems = createClearItemsMenuItem();
    JMenuItem clearAll = createClearAllMenuItem();

    this.add(copyToClipboard);
    this.add(new JSeparator());
    this.add(addToScope);
    this.add(addToSiteMap);
    this.add(new JSeparator());
    this.add(activeScan);
    this.add(sendToIntruder);
    this.add(sendToRepeater);
    this.add(sendToComparer);
    this.add(new JSeparator());
    this.add(highlightMenu);
    this.add(new JSeparator());
    this.add(clearItems);
    this.add(clearAll);
  }

  private JMenuItem createCopyToClipboardMenuItem() {
    JMenuItem copyToClipboard = new JMenuItem();

    table.addMouseListener(new MouseAdapter() {
      @Override
      public void mousePressed(MouseEvent e) {
        JTable source = (JTable) e.getSource();
        int row = source.rowAtPoint(e.getPoint());
        int column = source.columnAtPoint(e.getPoint());

        if (!source.isRowSelected(row))
          source.changeSelection(row, column, false, false);

        int index = table.getSelectedRow();
        HttpRequest httpRequest = getHttpRequestFromSelectedIndex(index);

        copyToClipboard.setText(httpRequest.url());
      }
    });

    copyToClipboard.addActionListener(e -> {
      int index = table.getSelectedRow();
      HttpRequest httpRequest = getHttpRequestFromSelectedIndex(index);

      Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(httpRequest.url()), null);
    });

    return copyToClipboard;
  }

  private void processSelectedRows(Consumer<Integer> action) {
    IntStream.of(table.getSelectedRows())
        .forEach(row -> {
          int index = (int) table.getValueAt(row, table.getColumn("#").getModelIndex());
          action.accept(index);
        });
  }

  private HttpRequest getHttpRequestFromSelectedIndex(int index) {
    ParserTableModel parserTableModel = (ParserTableModel) table.getModel();
    return parserTableModel.getHttpRequestAt(index);
  }

  private JMenuItem createAddToScopeMenuItem() {
    JMenuItem addToScope = new JMenuItem("Add to scope");

    addToScope.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestFromSelectedIndex(index);
      montoyaApi.scope().includeInScope(httpRequest.url());
    }));

    return addToScope;
  }

  private JMenuItem createAddToSiteMapMenuItem() {
    JMenuItem addToSiteMap = new JMenuItem("Add to site map");

    addToSiteMap.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestFromSelectedIndex(index);
      montoyaApi.siteMap().add(HttpRequestResponse.httpRequestResponse(httpRequest, null, null));
    }));

    return addToSiteMap;
  }

  private JMenuItem createActiveScanMenuItem() {
    JMenuItem activeScan = new JMenuItem("Do an active scan");

    activeScan.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestFromSelectedIndex(index);
      montoyaApi.scanner().startAudit(null).addRequest(httpRequest);
    }));

    return activeScan;
  }

  private JMenuItem createSendToIntruderMenuItem() {
    JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");

    sendToIntruder.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestFromSelectedIndex(index);
      montoyaApi.intruder().sendToIntruder(httpRequest);
    }));

    return sendToIntruder;
  }

  private JMenuItem createSendToRepeaterMenuItem() {
    JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");

    sendToRepeater.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestFromSelectedIndex(index);
      montoyaApi.repeater().sendToRepeater(httpRequest,
          String.format("%s -> %s %s",
              table.getValueAt(index, table.getColumn("Server").getModelIndex()),
              table.getValueAt(index, table.getColumn("Method").getModelIndex()),
              table.getValueAt(index, table.getColumn("Path").getModelIndex())));
    }));

    return sendToRepeater;
  }

  private JMenuItem createSendToComparerMenuItem() {
    JMenuItem sendToComparer = new JMenuItem("Send to Comparer");
    sendToComparer.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestFromSelectedIndex(index);
      montoyaApi.comparer().sendToComparer(httpRequest.toByteArray());
    }));

    return sendToComparer;
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

  private JMenuItem createClearItemsMenuItem() {
    JMenuItem clear = new JMenuItem("Clear item(s)");

    CustomTableCellRenderer renderer = (CustomTableCellRenderer) table.getDefaultRenderer(Object.class);

    clear.addActionListener(e -> {
      // Get the selected rows and sort them in reverse order
      List<Integer> selectedRows = IntStream.of(table.getSelectedRows())
          .boxed()
          .sorted(Collections.reverseOrder())
          .collect(Collectors.toList());

      // Remove the rows one by one from the table
      SwingUtilities.invokeLater(() -> {
        ParserTableModel tableModel = (ParserTableModel) table.getModel();

        for (Integer row : selectedRows) {
          int modelRow = table.convertRowIndexToModel(row);
          // Mapping view row to model row using a unique identifier
          Object rowId = table.getValueAt(row, table.getColumn("#").getModelIndex());

          tableModel.removeRow(modelRow);
          renderer.clearRowHighlightColor(rowId);
        }
      });

      // Updating the rows' index (reindexing table)
      IntStream.range(0, table.getRowCount())
          .forEach(row -> table.getModel().setValueAt(row, row, table.getColumn("#").getModelIndex()));
    });

    return clear;
  }

  private JMenuItem createClearAllMenuItem() {
    JMenuItem clearAll = new JMenuItem("Clear all");

    CustomTableCellRenderer renderer = (CustomTableCellRenderer) table.getDefaultRenderer(Object.class);

    clearAll.addActionListener(e -> {
      SwingUtilities.invokeLater(() -> {
        ParserTableModel tableModel = (ParserTableModel) table.getModel();
        tableModel.clear();
        renderer.clearAllRowHighlightColors();
      });
    });

    return clearAll;
  }
}
