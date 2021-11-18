/*
#    Copyright (C) 2016-2021 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. 
*/

package swurg.gui;

import static burp.BurpExtender.COPYRIGHT;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.Optional;
import java.util.prefs.Preferences;
import java.util.stream.Collectors;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import com.google.common.base.Strings;

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import swurg.process.Loader;
import swurg.utilities.LogEntry;

public class ParserPanel extends JPanel implements IMessageEditorController {

  private transient IBurpExtenderCallbacks callbacks;

  private JTable table;
  private transient TableRowSorter<TableModel> tableRowSorter;

  private JLabel statusLabel = new JLabel(COPYRIGHT);
  private JTextField resourceTextField = new JTextField(null, 64);
  private JTextField filterTextField = new JTextField(null, 32);

  private Model model;

  private transient IHttpRequestResponse currentlyDisplayedItem;
  private transient IMessageEditor requestViewer;

  public ParserPanel(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;

    initComponents();
  }

  private void initComponents() {
    this.setLayout(new BorderLayout());

    JPanel northPanel = new JPanel(new GridBagLayout());

    GridBagConstraints gridBagConstraints = new GridBagConstraints();

    gridBagConstraints.anchor = GridBagConstraints.CENTER;
    gridBagConstraints.gridy = 0;
    gridBagConstraints.insets = new Insets(4, 0, 0, 0);
    gridBagConstraints.weightx = 1.0;

    JPanel resourcePanel = new JPanel();
    resourcePanel.add(new JLabel("Parse file/URL:"));
    this.resourceTextField.setHorizontalAlignment(SwingConstants.CENTER);
    resourcePanel.add(this.resourceTextField);

    JButton resourceButton = new JButton("Browse/Load");
    resourceButton.setBackground(javax.swing.UIManager.getLookAndFeelDefaults().getColor("Burp.burpOrange"));
    resourceButton.setFont(new Font(resourceButton.getFont().getName(), Font.BOLD, resourceButton.getFont().getSize()));
    resourceButton
        .setForeground(javax.swing.UIManager.getLookAndFeelDefaults().getColor("Burp.primaryButtonForeground"));
    resourceButton.addActionListener(new LoadButtonListener());
    resourcePanel.add(resourceButton);

    northPanel.add(resourcePanel, gridBagConstraints);

    gridBagConstraints.anchor = GridBagConstraints.LINE_START;
    gridBagConstraints.gridy = 1;
    gridBagConstraints.insets = new Insets(0, 0, 4, 0);

    JPanel filterPanel = new JPanel();
    filterPanel.add(new JLabel("Filter (accepts regular expressions):"));
    this.filterTextField.getDocument().addDocumentListener(new DocumentListener() {
      private void process() {
        String regex = filterTextField.getText();

        if (Strings.isNullOrEmpty(regex)) {
          tableRowSorter.setRowFilter(null);
        } else {
          tableRowSorter.setRowFilter(RowFilter.regexFilter(regex));
        }
      }

      @Override
      public void insertUpdate(DocumentEvent e) {
        process();
      }

      @Override
      public void removeUpdate(DocumentEvent e) {
        process();
      }

      @Override
      public void changedUpdate(DocumentEvent e) {
        // Dummy comment
      }
    });
    filterPanel.add(this.filterTextField);

    northPanel.add(filterPanel, gridBagConstraints);

    initTable();

    JTabbedPane tabbedPane = new JTabbedPane();
    requestViewer = this.callbacks.createMessageEditor(this, true);
    tabbedPane.addTab("Request", requestViewer.getComponent());

    JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    splitPane.setTopComponent(new JScrollPane(this.table));
    splitPane.setBottomComponent(tabbedPane);

    JPanel southPanel = new JPanel();
    southPanel.add(this.statusLabel);

    this.add(northPanel, BorderLayout.NORTH);
    this.add(splitPane);
    this.add(southPanel, BorderLayout.SOUTH);
  }

  private void initTable() {
    this.table = new JTable() {
      @Override
      public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        HttpRequestResponse selectedRow = model.getLogEntries().stream().map(LogEntry::getHttpRequestResponse)
            .collect(Collectors.toList()).get(row);

        requestViewer.setMessage(selectedRow.getRequest(), true);
        currentlyDisplayedItem = selectedRow;

        super.changeSelection(row, col, toggle, extend);
      }
    };

    ContextMenu contextMenu = new ContextMenu(callbacks, this);

    this.table.addMouseListener(new MouseAdapter() {
      @Override
      public void mouseReleased(MouseEvent e) {
        int selectedRow = table.rowAtPoint(e.getPoint());

        if ((selectedRow >= 0 && selectedRow < table.getRowCount())
            && !table.getSelectionModel().isSelectedIndex(selectedRow)) {
          table.setRowSelectionInterval(selectedRow, selectedRow);
        }

        if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
          this.show(e);
        }

        contextMenu.setModel(model);
      }

      @Override
      public void mousePressed(MouseEvent e) {
        if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
          this.show(e);
        }
      }

      private void show(MouseEvent e) {
        contextMenu.show(e.getComponent(), e.getX(), e.getY());
      }
    });

    Object[] columns = { "#", "Method", "Server", "Path", "Parameters (inHeader, inQuery & inPath)", "Description" };
    Object[][] rows = {};
    this.table.setModel(new DefaultTableModel(rows, columns) {
      @Override
      public Class<?> getColumnClass(int column) {
        if (column == 0) {
          return Integer.class;
        }

        return super.getColumnClass(column);
      }

      @Override
      public boolean isCellEditable(int rows, int columns) {
        return false;
      }
    });

    this.table.setAutoCreateRowSorter(true);
    this.tableRowSorter = new TableRowSorter<>(this.table.getModel());
    this.table.setRowSorter(this.tableRowSorter);
  }

  public JTable getTable() {
    return this.table;
  }

  public void setModel(Model model) {
    this.model = model;
  }

  public void setResourceTextField(String resourceTextField) {
    this.resourceTextField.setText(resourceTextField);
  }

  public void printStatus(String status, Color color) {
    this.statusLabel.setForeground(color);
    this.statusLabel.setText(status);
  }

  class LoadButtonListener implements ActionListener {

    LoadButtonListener() {
      super();
    }

    public void actionPerformed(ActionEvent e) {
      if (e.getSource() instanceof JButton) {
        String resource = getResource((JButton) e.getSource());

        if (resource != null) {
          try {
            Loader loader = new Loader(callbacks);
            model.setLogEntries(loader.parseOpenAPI(loader.processOpenAPI(resource)));

            // Updating table model
            for (LogEntry entry : model.getLogEntries()) {
              ((DefaultTableModel) table.getModel())
                  .addRow(new Object[] { ((DefaultTableModel) table.getModel()).getRowCount(), entry.getHttpMethod(),
                      entry.getServer(), entry.getPathItem(), entry.getParameters(),
                      Optional.ofNullable(entry.getDescription()).orElse("N/A") });
            }

            printStatus(COPYRIGHT, javax.swing.UIManager.getLookAndFeelDefaults().getColor("TextField.foreground"));
          } catch (Exception e1) {
            callbacks.printError(String.format("%s -> %s", this.getClass().getName(), e1.getMessage()));
            printStatus(e1.getMessage(), javax.swing.UIManager.getLookAndFeelDefaults().getColor("Burp.burpError"));
          }
        }
      }
    }

    private String getResource(JButton button) {
      String resource = null;

      if (resourceTextField.getText().isEmpty()) {
        Preferences prefs = Preferences.userRoot().node(getClass().getName());
        JFileChooser fileChooser = new JFileChooser(prefs.get("LAST_USED_FOLDER", new File(".").getAbsolutePath()));
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("OpenAPI JSON File (*.json)", "json"));
        fileChooser
            .addChoosableFileFilter(new FileNameExtensionFilter("OpenAPI YAML File (*.yml, *.yaml)", "yaml", "yml"));

        if (fileChooser.showOpenDialog(button.getParent()) == JFileChooser.APPROVE_OPTION) {
          File file = fileChooser.getSelectedFile();
          resource = file.getAbsolutePath();
          resourceTextField.setText(resource);
          prefs.put("LAST_USED_FOLDER", fileChooser.getSelectedFile().getParent());
        }
      } else {
        resource = resourceTextField.getText();
      }

      return resource;
    }
  }

  @Override
  public byte[] getRequest() {
    return currentlyDisplayedItem.getRequest();
  }

  @Override
  public byte[] getResponse() {
    return currentlyDisplayedItem.getResponse();
  }

  @Override
  public IHttpService getHttpService() {
    return currentlyDisplayedItem.getHttpService();
  }
}
