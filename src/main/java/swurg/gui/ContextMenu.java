package swurg.gui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import swurg.utilities.LogEntry;

class ContextMenu extends JPopupMenu {

  private transient Map<Integer, List<Color>> highlightedRows = new HashMap<>();
  private MontoyaApi montoyaApi;
  private JTable table;
  private Model model;

  ContextMenu(MontoyaApi montoyaApi, ParserPanel tab) {
    this.montoyaApi = montoyaApi;
    this.table = tab.getTable();

    initComponents();
  }

  public void setModel(Model model) {
    this.model = model;
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
    return model.getLogEntries().stream()
        .map(LogEntry::getHttpRequest)
        .collect(Collectors.toList())
        .get(index);
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
      JMenuItem x = createHighlightMenuItem(color);

      highlightMenu.add(x);
    }

    return highlightMenu;
  }

  private void updateComponentColor(Component component, int viewRow, boolean isSelected) {
    int modelRow = table.convertRowIndexToModel(viewRow);
    Color foregroundColor = javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.foreground");
    Color backgroundColor;

    if (modelRow % 2 == 0) {
      backgroundColor = javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.background");
    } else {
      backgroundColor = javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.alternateRowColor");
    }

    if (highlightedRows.containsKey(modelRow)) {
      List<Color> colors = highlightedRows.get(modelRow);
      if (colors != null) {
        foregroundColor = colors.get(0);
        backgroundColor = colors.get(1);
      }
    }

    if (isSelected) {
      foregroundColor = javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.selectionForeground");
      backgroundColor = javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.selectionBackground");
    }

    component.setForeground(foregroundColor);
    component.setBackground(backgroundColor);
  }

  private JMenuItem createHighlightMenuItem(Color color) {
    JMenuItem menuItem = new JMenuItem();

    menuItem.setOpaque(true);
    menuItem.setBackground(color);
    menuItem.setForeground(color != null ? Color.BLACK : null);

    menuItem.addActionListener(e -> {
      IntStream.of(table.getSelectedRows())
          .forEach(row -> highlightedRows.put(row, color != null ? Arrays.asList(Color.BLACK, color) : null));

      table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
            int row, int column) {
          final Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row,
              column);

          updateComponentColor(component, row, isSelected);

          return component;
        }
      });
    });

    return menuItem;
  }

  private JMenuItem createClearItemsMenuItem() {
    JMenuItem clear = new JMenuItem("Clear item(s)");
    clear.addActionListener(e -> {
      // Get the selected rows and sort them in reverse order
      List<Integer> selectedRows = IntStream.of(table.getSelectedRows())
          .boxed()
          .sorted(Collections.reverseOrder())
          .collect(Collectors.toList());

      // Remove the rows one by one
      for (Integer row : selectedRows) {
        int modelRow = table.convertRowIndexToModel(row);
        int index = (int) table.getModel().getValueAt(modelRow, table.getColumn("#").getModelIndex());
        model.getLogEntries().remove(index);
        ((DefaultTableModel) table.getModel()).removeRow(modelRow);
        // Remove the highlighted rows that correspond to the removed rows
        highlightedRows.remove(table.convertRowIndexToModel(row));
      }

      // Setting logEntries to the newly shrinked list in order to fire the associated
      // events
      model.setLogEntries(model.getLogEntries());

      // Updating the rows' index (reindexing table)
      IntStream.range(0, table.getRowCount())
          .forEach(row -> table.getModel().setValueAt(row, row, table.getColumn("#").getModelIndex()));
    });

    return clear;
  }

  private JMenuItem createClearAllMenuItem() {
    JMenuItem clearAll = new JMenuItem("Clear all");

    clearAll.addActionListener(e -> {
      highlightedRows.clear();
      model.setLogEntries(new ArrayList<LogEntry>());
      ((DefaultTableModel) table.getModel()).setRowCount(0);
    });

    return clearAll;
  }
}
