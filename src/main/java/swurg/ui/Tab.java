/*
#    Copyright (C) 2016 Alexandre Teyar

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

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.ITab;
import io.swagger.models.HttpMethod;
import io.swagger.models.Operation;
import io.swagger.models.Path;
import io.swagger.models.Scheme;
import io.swagger.models.Swagger;
import io.swagger.models.parameters.Parameter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GraphicsEnvironment;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import swurg.process.Loader;
import swurg.utils.ExtensionHelper;

public class Tab implements ITab {

  private final ContextMenu contextMenu;
  private ExtensionHelper extensionHelper;

  private JPanel rootPanel;
  private JPanel swaggerPanel;
  private JTable table;
  private JPanel statusPanel;

  private List<HttpRequestResponse> httpRequestResponses;

  public Tab(IBurpExtenderCallbacks callbacks) {
    this.contextMenu = new ContextMenu(callbacks, this);
    this.extensionHelper = new ExtensionHelper(callbacks);
    this.httpRequestResponses = new ArrayList<>();

    initUI();
  }

  private void initUI() {
    this.rootPanel = new JPanel();
    this.rootPanel.setLayout(new BorderLayout());

    // file panel
    this.swaggerPanel = new JPanel();
    this.swaggerPanel.setLayout(new GridBagLayout());
    this.swaggerPanel.setPreferredSize(new Dimension(
        GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDisplayMode()
            .getWidth(),
        GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDisplayMode()
            .getHeight() / 10));
    this.swaggerPanel.add(new JLabel("Parse file/URL:"));
    this.swaggerPanel.add(new JTextField(null, 48));
    JButton button = new JButton("Browse/Load");
    button.addActionListener(new ButtonListener());
    this.swaggerPanel.add(button);

    // scroll table
    Object columns[] = {
        "#",
        "Method",
        "Host",
        "Protocol",
        "Base Path",
        "Endpoint",
        "Param"
    };
    Object rows[][] = {};
    this.table = new JTable(new DefaultTableModel(rows, columns) {
      @Override
      public boolean isCellEditable(
          int rows, int columns
      ) {
        return false;
      }
    });

    this.table.addMouseListener(new MouseAdapter() {
      @Override
      public void mouseReleased(MouseEvent e) {
        int selectedRow = table.rowAtPoint(e.getPoint());

        if (selectedRow >= 0 && selectedRow < table.getRowCount()) {
          if (!table.getSelectionModel().isSelectedIndex(selectedRow)) {
            table.setRowSelectionInterval(selectedRow, selectedRow);
          }
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

    // status panel
    this.statusPanel = new JPanel();
    this.statusPanel.add(new JLabel(COPYRIGHT));

    // parent container
    this.rootPanel.add(this.swaggerPanel, BorderLayout.NORTH);
    this.rootPanel.add(new JScrollPane(this.table));
    this.rootPanel.add(this.statusPanel, BorderLayout.SOUTH);
  }

  private String openFileExplorer() {
    JFileChooser jFileChooser = new JFileChooser();
    String resource = null;

    FileFilter filterJson = new FileNameExtensionFilter("Swagger JSON File (*.json)", "json");
    jFileChooser.addChoosableFileFilter(filterJson);
    FileFilter filterYml = new FileNameExtensionFilter("Swagger YAML File (*.yml, *.yaml)", "yaml",
        "yml");
    jFileChooser.addChoosableFileFilter(filterYml);

    jFileChooser.setFileFilter(filterYml);
    jFileChooser.setFileFilter(filterJson);

    if (jFileChooser.showOpenDialog(this.rootPanel) == JFileChooser.APPROVE_OPTION) {
      File file = jFileChooser.getSelectedFile();
      resource = file.getAbsolutePath();
      for (Component component : this.swaggerPanel.getComponents()) {
        if (component instanceof JTextField) {
          ((JTextField) component).setText(resource);
        }
      }
    }

    return resource;
  }

  private String getResource() {
    JTextField textField = null;
    String resource;

    for (Component component : this.swaggerPanel.getComponents()) {
      if (component instanceof JTextField) {
        textField = (JTextField) component;
      }
    }

    if (textField == null || textField.getText().isEmpty()) {
      resource = openFileExplorer();

      if (resource == null) {
        displayStatus(COPYRIGHT, Color.BLACK);
      }
    } else {
      resource = textField.getText();

      try {
        new URL(resource);
      } catch (MalformedURLException e) {
        File file = new File(resource);

        if (!file.exists()) {
          highlightFileTextField();
          displayStatus("File does not exist! Enter the full path to the file, or a valid URL.",
              Color.RED);
          resource = null;
        }
      }
    }

    return resource;
  }

  public void loadSwagger(Swagger swagger) {
    try {
      // add regex validation for host/ip
      if (swagger.getHost() == null || (swagger.getHost() != null && swagger.getHost().isEmpty())) {
        String host = JOptionPane.showInputDialog(
            "`host` field is missing.\nPlease enter one below" + "" + "" + ".\nFormat:"
                + " <host> or " +
                "<host:port>");
        swagger.setHost(host);
      }

      if (swagger.getSchemes() == null || (swagger.getSchemes() != null && swagger.getSchemes()
          .isEmpty())) {
        String scheme = "";

        while (!scheme.matches("HTTP|HTTPS|WS|WSS")) {
          scheme = JOptionPane.showInputDialog(
              "`scheme` field is missing.\nPlease enter one below" + ""
                  + ".\nAllowed values: HTTP, " +
                  "HTTPS, WS, WSS.");
        }
        swagger.addScheme(Scheme.valueOf(scheme));
      }

      String swaggerInfo =
          "Title: " + swagger.getInfo().getTitle() + " | " + "Version: " + swagger.getInfo()
              .getVersion
                  () +
              " | " + "Description: " + swagger
              .getInfo().getDescription();
      displayStatus(swaggerInfo, Color.BLACK);

      populateTable(swagger);
    } catch (Exception e) {
      displayStatus("Could not load the OpenAPI specification",
          Color.RED);
    }
  }

  JTable getTable() {
    return this.table;
  }

  void highlightFileTextField() {
    for (Component component : this.swaggerPanel.getComponents()) {
      if (component instanceof JTextField) {
        component.requestFocus();
        ((JTextField) component).selectAll();
      }
    }
  }

  // make the status fit the container - pack/resize
  void displayStatus(
      String status, Color color
  ) {
    for (Component component : this.statusPanel.getComponents()) {
      if (component instanceof JLabel) {
        ((JLabel) component).setText(status);
        component.setForeground(color);
      }
    }
  }

  private void populateTable(Swagger swagger) {
    DefaultTableModel defaultTableModel = (DefaultTableModel) this.table.getModel();
    List<Scheme> schemes = swagger.getSchemes();

    for (Scheme scheme : schemes) {
      for (Map.Entry<String, Path> path : swagger.getPaths().entrySet()) {
        for (Map.Entry<HttpMethod, Operation> operation : path.getValue().getOperationMap()
            .entrySet()) {
          StringBuilder stringBuilder = new StringBuilder();

          for (Parameter parameter : operation.getValue().getParameters()) {
            stringBuilder.append(parameter.getName()).append(", ");
          }

          if (stringBuilder.length() > 0) {
            stringBuilder.setLength(stringBuilder.length() - 2);
          }

          defaultTableModel.addRow(new Object[]{
              defaultTableModel.getRowCount() + 1,
              operation.getKey().toString(),
              swagger.getHost().split(":")[0],
              scheme.toValue().toUpperCase(),
              swagger.getBasePath(),
              path.getKey(),
              stringBuilder.toString()
          });

          this.httpRequestResponses.add(
              new HttpRequestResponse(
                  this.extensionHelper.getBurpExtensionHelpers().buildHttpService(
                      swagger.getHost().split(":")[0],
                      this.extensionHelper
                          .getPort(
                              swagger,
                              scheme
                          ),
                      this.extensionHelper
                          .isUseHttps(
                              scheme)
                  ),
                  this.extensionHelper.isUseHttps(scheme),
                  this.extensionHelper
                      .buildRequest(swagger, path,
                          operation
                      )
              ));

          resizeTable(table);
        }
      }
    }
  }

  private void resizeTable(JTable table) {
    TableColumnModel columnModel = table.getColumnModel();

    for (int column = 0; column < table.getColumnCount(); column++) {
      int width = 16; // min width

      for (int row = 0; row < table.getRowCount(); row++) {
        TableCellRenderer renderer = table.getCellRenderer(row, column);
        Component comp = table.prepareRenderer(renderer, row, column);
        width = Math.max(comp.getPreferredSize().width + 1, width);
      }

      if (width > 300) {
        width = 300;
      }

      columnModel.getColumn(column).setPreferredWidth(width);
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

  class ButtonListener implements ActionListener {

    ButtonListener() {
      super();
    }

    public void actionPerformed(ActionEvent e) {
      if (e.getSource() instanceof JButton) {
        String resource = getResource();
        Swagger swagger = new Loader().process(resource);
        loadSwagger(swagger);
      }
    }
  }
}
