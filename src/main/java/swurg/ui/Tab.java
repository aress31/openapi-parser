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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import swurg.process.Loader;
import swurg.utils.ExtensionHelper;

public class Tab implements ITab {

  private final ContextMenu contextMenu;
  private ExtensionHelper extensionHelper;

  private JPanel rootPanel;
  private JTable table;

  private JLabel statusLabel = new JLabel(COPYRIGHT);
  private JTextField resourceTextField = new JTextField(null, 48);

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
    JPanel swaggerPanel = new JPanel();
    swaggerPanel.setLayout(new GridBagLayout());
    swaggerPanel.setPreferredSize(new Dimension(
        GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDisplayMode()
            .getWidth(),
        GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDisplayMode()
            .getHeight() / 10));
    swaggerPanel.add(new JLabel("Parse file/URL:"));
    swaggerPanel.add(this.resourceTextField);
    JButton button = new JButton("Browse/Load");
    button.addActionListener(new ButtonListener());
    swaggerPanel.add(button);

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
    JPanel statusPanel = new JPanel();
    statusPanel.add(this.statusLabel);

    // parent container
    this.rootPanel.add(swaggerPanel, BorderLayout.NORTH);
    this.rootPanel.add(new JScrollPane(this.table));
    this.rootPanel.add(statusPanel, BorderLayout.SOUTH);
  }

  private String getResource() {
    String resource = null;

    if (this.resourceTextField.getText().isEmpty()) {
      JFileChooser fileChooser = new JFileChooser();
      fileChooser.addChoosableFileFilter(
          new FileNameExtensionFilter("Swagger JSON File (*.json)", "json"));
      fileChooser.addChoosableFileFilter(
          new FileNameExtensionFilter("Swagger YAML File (*.yml, *.yaml)", "yaml",
              "yml"));

      if (fileChooser.showOpenDialog(this.rootPanel) == JFileChooser.APPROVE_OPTION) {
        File file = fileChooser.getSelectedFile();
        resource = file.getAbsolutePath();
        resourceTextField.setText(resource);
      }
    } else {
      resource = this.resourceTextField.getText();
    }

    return resource;
  }

  JTable getTable() {
    return this.table;
  }

  public void printStatus(
      String status, Color color
  ) {
    this.statusLabel.setText(status);
    this.statusLabel.setForeground(color);
  }

  public void populateTable(Swagger swagger) {
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

          defaultTableModel.addRow(new Object[]{
              defaultTableModel.getRowCount(),
              operation.getKey().toString(),
              swagger.getHost().split(":")[0],
              scheme.toValue().toUpperCase(),
              swagger.getBasePath(),
              path.getKey(),
              stringBuilder.toString()
          });
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

  class ButtonListener implements ActionListener {

    ButtonListener() {
      super();
    }

    public void actionPerformed(ActionEvent e) {
      if (e.getSource() instanceof JButton) {
        String resource = getResource();

        try {
          Swagger swagger = new Loader().process(resource);
          populateTable(swagger);
          printStatus(COPYRIGHT, Color.BLACK);
        } catch (IllegalArgumentException | NullPointerException e1) {
          printStatus(e1.getMessage(), Color.RED);
          resourceTextField.requestFocus();
        }
      }
    }
  }
}
