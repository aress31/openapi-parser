/*
#    Copyright (C) 2016 Alexandre Teyar

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

package swurg.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

@SuppressWarnings("serial")
class ContextMenu extends JPopupMenu {

  private final Map<Integer, List<Color>> highlightedRows = new HashMap<>();
  // private final Map<Integer, Color> highlightedRows = new HashMap<>();
  private List<HttpRequestResponse> httpRequestResponses;

  // For debugging purposes
  private PrintWriter stdOut, stdErr;

  ContextMenu(IBurpExtenderCallbacks callbacks, Tab tab) {
    // For debugging purposes
    this.stdErr = new PrintWriter(callbacks.getStderr(), true);
    this.stdOut = new PrintWriter(callbacks.getStdout(), true);

    JMenuItem copyToClipboard = new JMenuItem();

    tab.getTable().addMouseListener(new MouseAdapter() {
      public void mousePressed(MouseEvent e) {
        JTable source = (JTable) e.getSource();
        int row = source.rowAtPoint(e.getPoint());
        int column = source.columnAtPoint(e.getPoint());

        if (!source.isRowSelected(row))
          source.changeSelection(row, column, false, false);

        copyToClipboard
            .setText(tab.getTable().getValueAt(row, tab.getTable().getColumn("Server").getModelIndex()).toString()
                + tab.getTable().getValueAt(row, tab.getTable().getColumn("Path").getModelIndex()).toString());
      }
    });

    copyToClipboard.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard()
        .setContents(new StringSelection(copyToClipboard.getText()), null));

    JMenuItem addToScope = new JMenuItem("Add to scope");
    addToScope.addActionListener(e -> {
      try {
        callbacks.includeInScope(new URL(tab.getTable()
            .getValueAt(tab.getTable().getSelectedRow(), tab.getTable().getColumn("Server").getModelIndex()).toString()
            + tab.getTable()
                .getValueAt(tab.getTable().getSelectedRow(), tab.getTable().getColumn("Path").getModelIndex())
                .toString()));
      } catch (MalformedURLException e1) {
        // TODO Auto-generated catch block
        e1.printStackTrace();
      }
    });

    JMenuItem addToSiteMap = new JMenuItem("Add to site map");
    addToSiteMap.addActionListener(e -> IntStream.of(tab.getTable().getSelectedRows()).forEach(row -> {
      int index = (int) tab.getTable().getValueAt(row, tab.getTable().getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
      callbacks.addToSiteMap(httpRequestResponse);
    }));

    JMenuItem activeScan = new JMenuItem("Do an active scan");
    activeScan.addActionListener(e -> IntStream.of(tab.getTable().getSelectedRows()).forEach(row -> {
      int index = (int) tab.getTable().getValueAt(row, tab.getTable().getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
      callbacks.doActiveScan(httpRequestResponse.getHttpService().getHost(),
          httpRequestResponse.getHttpService().getPort(), httpRequestResponse.isUseHttps(),
          httpRequestResponse.getRequest());
    }));

    JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
    sendToIntruder.addActionListener(e -> IntStream.of(tab.getTable().getSelectedRows()).forEach(row -> {
      int index = (int) tab.getTable().getValueAt(row, tab.getTable().getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
      callbacks.sendToIntruder(httpRequestResponse.getHttpService().getHost(),
          httpRequestResponse.getHttpService().getPort(), httpRequestResponse.isUseHttps(),
          httpRequestResponse.getRequest());
    }));

    JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
    sendToRepeater.addActionListener(e -> IntStream.of(tab.getTable().getSelectedRows()).forEach(row -> {
      int index = (int) tab.getTable().getValueAt(row, tab.getTable().getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
      callbacks.sendToRepeater(httpRequestResponse.getHttpService().getHost(),
          httpRequestResponse.getHttpService().getPort(), httpRequestResponse.isUseHttps(),
          httpRequestResponse.getRequest(),
          String.format("%s -> %s %s",
              tab.getTable().getValueAt(row, tab.getTable().getColumn("Server").getModelIndex()),
              tab.getTable().getValueAt(row, tab.getTable().getColumn("Method").getModelIndex()),
              tab.getTable().getValueAt(row, tab.getTable().getColumn("Path").getModelIndex())));
    }));

    JMenuItem sendToComparer = new JMenuItem("Send to Comparer");
    sendToComparer.addActionListener(e -> IntStream.of(tab.getTable().getSelectedRows()).forEach(row -> {
      int index = (int) tab.getTable().getValueAt(row, tab.getTable().getColumn("#").getModelIndex());
      HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
      callbacks.sendToComparer(httpRequestResponse.getRequest());
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

      x.addHierarchyListener(e -> x.setText(tab.getTable()
          .getValueAt(tab.getTable().getSelectedRow(), tab.getTable().getColumn("Server").getModelIndex()).toString()));

      x.addActionListener(e -> {
        IntStream.of(tab.getTable().getSelectedRows())
            .forEach(row -> this.highlightedRows.put(row, color != null ? Arrays.asList(Color.BLACK, color) : null));

        tab.getTable().setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
          @Override
          public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
              boolean hasFocus, int row, int column) {
            final Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row,
                column);

            // stdOut.println(String.format("%s -> %s", row, highlightedRows.get(row)));

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
      // iterating the indices in decreasing order to not mess up the table shifting
      IntStream.of(tab.getTable().getSelectedRows()).boxed().map(row -> tab.getTable().convertRowIndexToModel(row))
          .sorted(Collections.reverseOrder()).forEach(row -> {
            int index = (int) tab.getTable().getValueAt(row, tab.getTable().getColumn("#").getModelIndex());
            this.httpRequestResponses.remove(index);
            ((DefaultTableModel) tab.getTable().getModel()).removeRow(row);
          });

      // updating the rows' index (reindexing table)
      IntStream.rangeClosed(0, tab.getTable().getRowCount()).forEach(
          row -> tab.getTable().getModel().setValueAt(row, row, tab.getTable().getColumn("#").getModelIndex()));
    });

    JMenuItem clearAll = new JMenuItem("Clear all");
    clearAll.addActionListener(e -> {
      this.httpRequestResponses.clear();
      ((DefaultTableModel) tab.getTable().getModel()).setRowCount(0);
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

  void setHttpRequestResponses(List<HttpRequestResponse> httpRequestResponses) {
    this.httpRequestResponses = httpRequestResponses;
  }
}
