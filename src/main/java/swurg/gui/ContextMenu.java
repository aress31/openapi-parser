/*
#    Copyright (C) 2016-2022 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copyToClipboard of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. 
*/

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
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import swurg.utilities.LogEntry;

class ContextMenu extends JPopupMenu {

  private final Map<Integer, List<Color>> highlightedRows = new HashMap<>();

  private transient IBurpExtenderCallbacks callbacks;

  private JTable table;

  private Model model;

  ContextMenu(IBurpExtenderCallbacks callbacks, ParserPanel tab) {
    this.callbacks = callbacks;
    this.table = tab.getTable();

    initComponents();
  }

  public void setModel(Model model) {
    this.model = model;
  }

  private void initComponents() {
    JMenuItem copyToClipboard = new JMenuItem();

    this.table.addMouseListener(new MouseAdapter() {
      @Override
      public void mousePressed(MouseEvent e) {
        JTable source = (JTable) e.getSource();
        int row = source.rowAtPoint(e.getPoint());
        int column = source.columnAtPoint(e.getPoint());

        if (!source.isRowSelected(row))
          source.changeSelection(row, column, false, false);

        int index = table.getSelectedRow();
        HttpRequestResponse httpRequestResponse = model.getLogEntries().stream().map(LogEntry::getHttpRequestResponse)
            .collect(Collectors.toList()).get(index);

        copyToClipboard.setText(callbacks.getHelpers()
            .analyzeRequest(httpRequestResponse.getHttpService(), httpRequestResponse.getRequest()).getUrl()
            .toString());
      }
    });

    copyToClipboard.addActionListener(e -> {
      int index = this.table.getSelectedRow();
      HttpRequestResponse httpRequestResponse = this.model.getLogEntries().stream()
          .map(LogEntry::getHttpRequestResponse).collect(Collectors.toList()).get(index);

      Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(this.callbacks.getHelpers()
          .analyzeRequest(httpRequestResponse.getHttpService(), httpRequestResponse.getRequest()).getUrl().toString()),
          null);
    });

    JMenuItem addToScope = new JMenuItem("Add to scope");
    addToScope.addActionListener(e -> IntStream.of(this.table.getSelectedRows()).forEach(row -> {
      int index = (int) this.table.getValueAt(row, this.table.getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.model.getLogEntries().stream()
          .map(LogEntry::getHttpRequestResponse).collect(Collectors.toList()).get(index);

      this.callbacks.includeInScope(this.callbacks.getHelpers()
          .analyzeRequest(httpRequestResponse.getHttpService(), httpRequestResponse.getRequest()).getUrl());
    }));

    JMenuItem addToSiteMap = new JMenuItem("Add to site map");
    addToSiteMap.addActionListener(e -> IntStream.of(this.table.getSelectedRows()).forEach(row -> {
      int index = (int) this.table.getValueAt(row, this.table.getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.model.getLogEntries().stream()
          .map(LogEntry::getHttpRequestResponse).collect(Collectors.toList()).get(index);

      this.callbacks.addToSiteMap(httpRequestResponse);
    }));

    JMenuItem activeScan = new JMenuItem("Do an active scan");
    activeScan.addActionListener(e -> IntStream.of(this.table.getSelectedRows()).forEach(row -> {
      int index = (int) this.table.getValueAt(row, this.table.getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.model.getLogEntries().stream()
          .map(LogEntry::getHttpRequestResponse).collect(Collectors.toList()).get(index);

      this.callbacks.doActiveScan(httpRequestResponse.getHttpService().getHost(),
          httpRequestResponse.getHttpService().getPort(), httpRequestResponse.isUseHttps(),
          httpRequestResponse.getRequest());
    }));

    JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
    sendToIntruder.addActionListener(e -> IntStream.of(this.table.getSelectedRows()).forEach(row -> {
      int index = (int) this.table.getValueAt(row, this.table.getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.model.getLogEntries().stream()
          .map(LogEntry::getHttpRequestResponse).collect(Collectors.toList()).get(index);

      this.callbacks.sendToIntruder(httpRequestResponse.getHttpService().getHost(),
          httpRequestResponse.getHttpService().getPort(), httpRequestResponse.isUseHttps(),
          httpRequestResponse.getRequest());
    }));

    JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
    sendToRepeater.addActionListener(e -> IntStream.of(this.table.getSelectedRows()).forEach(row -> {
      int index = (int) this.table.getValueAt(row, this.table.getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.model.getLogEntries().stream()
          .map(LogEntry::getHttpRequestResponse).collect(Collectors.toList()).get(index);

      this.callbacks.sendToRepeater(httpRequestResponse.getHttpService().getHost(),
          httpRequestResponse.getHttpService().getPort(), httpRequestResponse.isUseHttps(),
          httpRequestResponse.getRequest(),
          String.format("%s -> %s %s", this.table.getValueAt(row, this.table.getColumn("Server").getModelIndex()),
              this.table.getValueAt(row, this.table.getColumn("Method").getModelIndex()),
              this.table.getValueAt(row, this.table.getColumn("Path").getModelIndex())));
    }));

    JMenuItem sendToComparer = new JMenuItem("Send to Comparer");
    sendToComparer.addActionListener(e -> IntStream.of(this.table.getSelectedRows()).forEach(row -> {
      int index = (int) this.table.getValueAt(row, this.table.getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.model.getLogEntries().stream()
          .map(LogEntry::getHttpRequestResponse).collect(Collectors.toList()).get(index);

      this.callbacks.sendToComparer(httpRequestResponse.getRequest());
    }));

    JMenu highlightMenu = new JMenu("Highlight");

    // Add null
    for (Color color : Arrays.asList(null, Color.RED, Color.ORANGE, Color.YELLOW, Color.GREEN, Color.BLUE,
        Color.MAGENTA, Color.PINK, Color.GRAY)) {
      final JMenuItem x = new JMenuItem();
      x.setOpaque(true);
      x.setBackground(color);
      x.setForeground(color != null ? Color.BLACK : null);

      highlightMenu.add(x);

      x.addHierarchyListener(e -> x.setText(this.table
          .getValueAt(this.table.getSelectedRow(), this.table.getColumn("Server").getModelIndex()).toString()));

      x.addActionListener(e -> {
        IntStream.of(this.table.getSelectedRows())
            .forEach(row -> this.highlightedRows.put(row, color != null ? Arrays.asList(Color.BLACK, color) : null));

        this.table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
          @Override
          public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
              boolean hasFocus, int row, int column) {
            final Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row,
                column);

            if (highlightedRows.containsKey(row) && highlightedRows.get(row) != null) {
              component.setForeground(
                  isSelected ? highlightedRows.get(row).get(0).darker() : highlightedRows.get(row).get(0));
              component.setBackground(
                  isSelected ? highlightedRows.get(row).get(1).brighter() : highlightedRows.get(row).get(1));
            } else {
              if (row % 2 == 0) {
                component.setBackground(javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.background"));
              } else {
                component
                    .setBackground(javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.alternateRowColor"));
              }

              component.setForeground(javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.foreground"));
            }

            if (isSelected) {
              component
                  .setForeground(javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.selectionForeground"));
              component
                  .setBackground(javax.swing.UIManager.getLookAndFeelDefaults().getColor("Table.selectionBackground"));
            }

            return component;
          }
        });
      });
    }

    JMenuItem clear = new JMenuItem("Clear item(s)");
    clear.addActionListener(e -> {
      // iterating the indices in de creasing order to not mess up the table shifting
      IntStream.of(this.table.getSelectedRows()).boxed().map(row -> this.table.convertRowIndexToModel(row))
          .sorted(Collections.reverseOrder()).forEach(row -> {
            int index = (int) this.table.getValueAt(row, this.table.getColumn("#").getModelIndex());
            this.model.getLogEntries().remove(index);
            ((DefaultTableModel) this.table.getModel()).removeRow(row);
          });

      // Setting logEntries to the newly shrinked list in order to fire the associated
      // events
      this.model.setLogEntries(this.model.getLogEntries());

      // updating the rows' index (reindexing table)
      IntStream.rangeClosed(0, this.table.getRowCount())
          .forEach(row -> this.table.getModel().setValueAt(row, row, this.table.getColumn("#").getModelIndex()));
    });

    JMenuItem clearAll = new JMenuItem("Clear all");
    clearAll.addActionListener(e -> {
      this.highlightedRows.clear();
      this.model.setLogEntries(new ArrayList<LogEntry>());
      ((DefaultTableModel) this.table.getModel()).setRowCount(0);
    });

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
    this.add(clear);
    this.add(clearAll);
  }
}
