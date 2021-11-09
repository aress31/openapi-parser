/*
#    statusLabel (C) 2016 Alexandre Teyar

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

package swurg.ui;

import static burp.BurpExtender.COPYRIGHT;
import static burp.BurpExtender.EXTENSION;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
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
import burp.ITab;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.servers.Server;
import swurg.process.Loader;
import swurg.utils.ExtensionHelper;

public class Tab implements ITab {

  private final ContextMenu contextMenu;
  private ExtensionHelper extensionHelper;
  private IBurpExtenderCallbacks callbacks;

  private JPanel rootPanel;
  private JTable table;
  private TableRowSorter<TableModel> tableRowSorter;

  private JLabel statusLabel = new JLabel(COPYRIGHT);
  private JTextField resourceTextField = new JTextField(null, 64);
  private JTextField filterTextField = new JTextField(null, 36);

  private List<HttpRequestResponse> httpRequestResponses;

  public Tab(IBurpExtenderCallbacks callbacks) {
    this.extensionHelper = new ExtensionHelper(callbacks);
    this.httpRequestResponses = new ArrayList<>();

    // For debugging purposes
    this.callbacks = callbacks;

    initUI();

    this.contextMenu = new ContextMenu(callbacks, this);
  }

  private void initUI() {
    this.rootPanel = new JPanel(new BorderLayout());

    // file panel
    JPanel topPanel = new JPanel(new GridBagLayout());
    GridBagConstraints gridBagConstraints = new GridBagConstraints();

    gridBagConstraints.anchor = GridBagConstraints.CENTER;
    gridBagConstraints.insets = new Insets(8, 0, 0, 0);
    gridBagConstraints.weightx = 1.0;
    JPanel resourcePanel = new JPanel();
    resourcePanel.add(new JLabel("Parse file/URL:"));
    this.resourceTextField.setHorizontalAlignment(SwingConstants.CENTER);
    resourcePanel.add(this.resourceTextField);
    JButton resourceButton = new JButton("Browse/Load");
    resourceButton.addActionListener(new LoadButtonListener());
    resourcePanel.add(resourceButton);
    topPanel.add(resourcePanel, gridBagConstraints);

    gridBagConstraints.anchor = GridBagConstraints.LINE_START;
    gridBagConstraints.insets = new Insets(0, 0, 4, 0);
    gridBagConstraints.gridy = 1;
    JPanel filerPanel = new JPanel();
    filerPanel.add(new JLabel("Filter (accepts regular expressions):"));
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
      }
    });
    filerPanel.add(this.filterTextField);
    topPanel.add(filerPanel, gridBagConstraints);

    // scroll table
    Object[] columns = { "#", "Method", "Server", "Path", "Parameters", "Description" };
    Object[][] rows = {};
    this.table = new JTable(new DefaultTableModel(rows, columns) {
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

        contextMenu.setHttpRequestResponses(httpRequestResponses);
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

    // enable column sorting
    this.table.setAutoCreateRowSorter(true);
    // enable table filtering
    this.tableRowSorter = new TableRowSorter<>(this.table.getModel());
    this.table.setRowSorter(tableRowSorter);

    // status panel
    JPanel bottomPanel = new JPanel();
    bottomPanel.add(this.statusLabel);

    // parent container
    this.rootPanel.add(topPanel, BorderLayout.NORTH);
    this.rootPanel.add(new JScrollPane(this.table));
    this.rootPanel.add(bottomPanel, BorderLayout.SOUTH);
  }

  JTable getTable() {
    return this.table;
  }

  public void printStatus(String status, Color color) {
    this.statusLabel.setText(status);
    this.statusLabel.setForeground(color);
  }

  public void populateTable(OpenAPI openAPI) {
    DefaultTableModel defaultTableModel = (DefaultTableModel) this.table.getModel();

    for (Server server : openAPI.getServers()) {
      for (Map.Entry<String, PathItem> pathItem : openAPI.getPaths().entrySet()) {
        Map<String, Operation> operationMap = new HashMap<>();
        operationMap.put("DELETE", pathItem.getValue().getDelete());
        operationMap.put("GET", pathItem.getValue().getGet());
        operationMap.put("HEAD", pathItem.getValue().getHead());
        operationMap.put("PATCH", pathItem.getValue().getPatch());
        operationMap.put("POST", pathItem.getValue().getPost());
        operationMap.put("PUT", pathItem.getValue().getPut());
        operationMap.put("TRACE", pathItem.getValue().getTrace());

        // create different maps for different methods merge them and iterate them
        for (Map.Entry<String, Operation> operation : operationMap.entrySet()) {
          if (operation.getValue() != null) {
            StringJoiner stringJoiner = new StringJoiner(", ");

            if (operation.getValue().getParameters() != null) {
              for (Parameter parameter : operation.getValue().getParameters()) {
                stringJoiner.add(parameter.getName());
              }
            }

            try {
              URI uri = new URI(server.getUrl());
              int port = uri.getScheme().equals("http") ? 80 : 443;

              HttpRequestResponse httpRequestResponse = new HttpRequestResponse(
                  this.extensionHelper.getBurpExtensionHelpers().buildHttpService(uri.getHost(), port, port == 443),
                  uri.getPort() == 443, this.extensionHelper.buildRequest(uri, pathItem, operation));

              this.httpRequestResponses.add(httpRequestResponse);
            } catch (URISyntaxException e) {
              this.callbacks.printError(e.getMessage());
              printStatus(e.getMessage(), Color.RED);
            }

            defaultTableModel.addRow(new Object[] { defaultTableModel.getRowCount(), operation.getKey(),
                server.getUrl(), pathItem.getKey(), stringJoiner.toString(),
                Optional.ofNullable(operation.getValue().getDescription()).orElse("N/A") });
          }
        }
      }
    }
  }

  @Override
  public Component getUiComponent() {
    return this.rootPanel;
  }

  @Override
  public String getTabCaption() {
    return EXTENSION;
  }

  class LoadButtonListener implements ActionListener {

    LoadButtonListener() {
      super();
    }

    public void actionPerformed(ActionEvent e) {
      if (e.getSource() instanceof JButton) {
        String resource = getResource();

        try {
          OpenAPI openAPI = new Loader().process(callbacks, resource);
          populateTable(openAPI);
          printStatus(COPYRIGHT, javax.swing.UIManager.getLookAndFeelDefaults().getColor("TextField.foreground"));
        } catch (Exception e1) {
          callbacks.printError(e1.getMessage());
          printStatus(e1.getMessage(), Color.RED);
          resourceTextField.requestFocus();
        }
      }
    }

    private String getResource() {
      String resource = null;

      if (resourceTextField.getText().isEmpty()) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("OpenAPI JSON File (*.json)", "json"));
        fileChooser
            .addChoosableFileFilter(new FileNameExtensionFilter("OpenAPI YAML File (*.yml, *.yaml)", "yaml", "yml"));

        if (fileChooser.showOpenDialog(rootPanel) == JFileChooser.APPROVE_OPTION) {
          File file = fileChooser.getSelectedFile();
          resource = file.getAbsolutePath();
          resourceTextField.setText(resource);
        }
      } else {
        resource = resourceTextField.getText();
      }

      return resource;
    }
  }
}
