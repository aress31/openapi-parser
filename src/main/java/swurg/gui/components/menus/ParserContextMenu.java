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
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
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
    JMenuItem sendToActiveScan = createSendToActiveScanMenuItem();
    JMenuItem sendToPassiveScan = createSendToPassiveScanMenuItem();
    JMenuItem sendToIntruder = createSendToIntruderMenuItem();
    JMenuItem sendToRepeater = createSendToRepeaterMenuItem();
    JMenuItem sendToOrganizer = createSendToOrganizerMenuItem();
    JMenuItem sendToComparer = createSendToComparerMenuItem();
    JMenu highlightMenu = createHighlightMenu();
    JMenuItem clearItems = createClearItemsMenuItem();
    JMenuItem clearAll = createClearAllMenuItem();

    this.add(copyToClipboard);
    this.add(new JSeparator());
    this.add(addToScope);
    this.add(new JSeparator());
    this.add(sendToPassiveScan);
    this.add(sendToActiveScan);
    this.add(new JSeparator());
    this.add(sendToIntruder);
    this.add(sendToRepeater);
    this.add(sendToOrganizer);
    this.add(sendToComparer);
    this.add(new JSeparator());
    this.add(highlightMenu);
    this.add(clearItems);
    this.add(clearAll);
    this.add(new JSeparator());
    this.add(addToSiteMap);
  }

  private HttpRequest getHttpRequestAt(int index) {
    ParserTableModel parserTableModel = (ParserTableModel) table.getModel();
    return parserTableModel.getMyHttpRequests().get(index).getHttpRequest();
  }

  private void processSelectedRows(Consumer<Integer> action) {
    IntStream.of(table.getSelectedRows())
        .forEach(row -> {
          int index = (int) table.getValueAt(row, table.getColumn("#").getModelIndex());
          action.accept(index);
        });
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
        HttpRequest httpRequest = getHttpRequestAt(index);

        copyToClipboard.setText(httpRequest.url());
      }
    });

    copyToClipboard.addActionListener(e -> {
      int index = table.getSelectedRow();
      HttpRequest httpRequest = getHttpRequestAt(index);

      Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(httpRequest.url()), null);
    });

    return copyToClipboard;
  }

  private JMenuItem createAddToScopeMenuItem() {
    JMenuItem addToScope = new JMenuItem("Add to scope");

    addToScope.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestAt(index);
      montoyaApi.scope().includeInScope(httpRequest.url());
    }));

    return addToScope;
  }

  private JMenuItem createSendToPassiveScanMenuItem() {
    JMenuItem sendToScanner = new JMenuItem("Do passive scan");

    sendToScanner.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestAt(index);
      montoyaApi.scanner()
          .startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS))
          .addRequest(httpRequest);
    }));

    return sendToScanner;
  }

  private JMenuItem createSendToActiveScanMenuItem() {
    JMenuItem sendToScanner = new JMenuItem("Do active scan");

    sendToScanner.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestAt(index);
      montoyaApi.scanner()
          .startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS))
          .addRequest(httpRequest);
    }));

    return sendToScanner;
  }

  private JMenuItem createSendToIntruderMenuItem() {
    JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");

    sendToIntruder.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestAt(index);
      montoyaApi.intruder().sendToIntruder(httpRequest);
    }));

    return sendToIntruder;
  }

  private JMenuItem createSendToRepeaterMenuItem() {
    JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");

    sendToRepeater.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestAt(index);
      montoyaApi.repeater().sendToRepeater(httpRequest,
          String.format("%s -> %s %s",
              table.getValueAt(index, table.getColumn("Server").getModelIndex()),
              table.getValueAt(index, table.getColumn("Method").getModelIndex()),
              table.getValueAt(index, table.getColumn("Path").getModelIndex())));
    }));

    return sendToRepeater;
  }

  private JMenuItem createSendToOrganizerMenuItem() {
    JMenuItem sendToOrganizer = new JMenuItem("Send to Organizer");

    sendToOrganizer.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestAt(index);
      montoyaApi.organizer().sendToOrganizer(httpRequest);
    }));

    return sendToOrganizer;
  }

  private JMenuItem createSendToComparerMenuItem() {
    JMenuItem sendToComparer = new JMenuItem("Send to Comparer (request)");
    sendToComparer.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestAt(index);
      montoyaApi.comparer().sendToComparer(httpRequest.toByteArray());
    }));

    return sendToComparer;
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

  private JMenuItem createClearItemsMenuItem() {
    JMenuItem clear = new JMenuItem("Delete item");

    CustomTableCellRenderer renderer = (CustomTableCellRenderer) table.getDefaultRenderer(Object.class);

    clear.addActionListener(e -> {
      // Retrieve the selected rows and arrange them in descending order.
      List<Integer> selectedRows = IntStream.of(table.getSelectedRows())
          .boxed()
          .sorted(Collections.reverseOrder())
          .collect(Collectors.toList());

      // Remove rows individually from the table.
      SwingUtilities.invokeLater(() -> {
        ParserTableModel tableModel = (ParserTableModel) table.getModel();

        selectedRows.forEach(index -> {
          int modelRow = table.convertRowIndexToModel(index);
          tableModel.removeRow(modelRow);
          renderer.clearRowHighlightColor(index);
        });
      });

      // Reindexing the table by updating the rows' indices.
      IntStream.range(0, table.getRowCount())
          .forEach(row -> table.getModel().setValueAt(row, row, table.getColumn("#").getModelIndex()));
    });

    return clear;
  }

  private JMenuItem createClearAllMenuItem() {
    JMenuItem clearAll = new JMenuItem("Clear log");

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

  private JMenuItem createAddToSiteMapMenuItem() {
    JMenuItem addToSiteMap = new JMenuItem("Add to site map");

    addToSiteMap.addActionListener(e -> processSelectedRows(index -> {
      HttpRequest httpRequest = getHttpRequestAt(index);
      montoyaApi.siteMap().add(HttpRequestResponse.httpRequestResponse(httpRequest, HttpResponse.httpResponse()));
    }));

    return addToSiteMap;
  }
}
