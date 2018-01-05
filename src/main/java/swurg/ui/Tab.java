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

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.ITab;
import io.swagger.models.*;
import io.swagger.models.parameters.Parameter;
import swurg.process.Loader;
import swurg.utils.ExtensionHelper;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Tab implements ITab {
    private final ContextMenu contextMenu;
    private ExtensionHelper extensionHelper;

    private PrintWriter stderr;
    private PrintWriter stdout;

    private JPanel rootPanel;
    private JPanel filePanel;
    private JTable table;
    private JPanel statusPanel;

    private String copyrightNotice = "Copyright \u00a9 2016 - 2018 Alexandre Teyar All Rights Reserved";
    private List<HttpRequestResponse> httpRequestResponses;

    public Tab(IBurpExtenderCallbacks callbacks) {
        this.contextMenu = new ContextMenu(callbacks, this.httpRequestResponses, this);
        this.extensionHelper = new ExtensionHelper(callbacks);
        this.httpRequestResponses = new ArrayList<>();
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        // file panel
        this.filePanel = new JPanel();
        this.filePanel.setName("filePanel");
        this.filePanel.add(new JLabel("Parse file/URL:"));
        this.filePanel.add(new JTextField(null, 48));
        JButton button = new JButton("Browse/Load");
        button.addActionListener(new ButtonListener());
        this.filePanel.add(button);

        // scroll table
        Object columns[] = {"#", "Method", "Host", "Protocol", "Base Path", "Endpoint", "Param"};
        Object rows[][] = {};
        this.table = new JTable(new DefaultTableModel(rows, columns) {
            @Override
            public boolean isCellEditable(int rows, int columns) {
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
        this.statusPanel.setName("statusPanel");
        this.statusPanel.add(new JLabel(this.copyrightNotice));

        // parent container
        this.rootPanel = new JPanel();
        this.rootPanel.setName("rootPanel");
        this.rootPanel.setLayout(new BorderLayout());
        this.rootPanel.add(this.filePanel, BorderLayout.NORTH);
        this.rootPanel.add(new JScrollPane(this.table));
        this.rootPanel.add(this.statusPanel, BorderLayout.SOUTH);

        this.stdout.println("`Swagger Parser` tab created");
    }

    private String openFileExplorer() {
        JFileChooser jFileChooser = new JFileChooser();
        String resource = null;

        FileFilter filterJson = new FileNameExtensionFilter("Swagger JSON File (*.json)", "json");
        jFileChooser.addChoosableFileFilter(filterJson);
        FileFilter filterYml = new FileNameExtensionFilter("Swagger YAML File (*.yml, *.yaml)", "yaml", "yml");
        jFileChooser.addChoosableFileFilter(filterYml);

        jFileChooser.setFileFilter(filterYml);
        jFileChooser.setFileFilter(filterJson);

        if (jFileChooser.showOpenDialog(this.rootPanel) == JFileChooser.APPROVE_OPTION) {
            File file = jFileChooser.getSelectedFile();
            resource = file.getAbsolutePath();
            for (Component component : this.filePanel.getComponents()) {
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

        for (Component component : this.filePanel.getComponents()) {
            if (component instanceof JTextField) {
                textField = (JTextField) component;
            }
        }

        if (textField == null || textField.getText().isEmpty()) {
            resource = openFileExplorer();

            if (resource == null) {
                displayStatus(this.copyrightNotice, Color.BLACK);
            }
        } else {
            resource = textField.getText();

            try {
                new URL(resource);
            } catch (MalformedURLException ex) {
                File file = new File(resource);

                if (!file.exists()) {
                    displayStatus("File does not exist! Enter the full path to the file, or a valid URL.", Color.RED);
                    textField.requestFocus();
                    textField.selectAll();
                    resource = null;
                }
            }
        }

        return resource;
    }

    public void loadSwagger(Swagger swagger) {
        try {
            // add regex validation
            if (swagger.getHost() == null || (swagger.getHost() != null && swagger.getHost().isEmpty())) {
                String host = JOptionPane.showInputDialog("`host` field is missing.\nPlease enter one below" + "" +
                                                                  "" + ".\nFormat:" + " <host> or <host:port>");
                swagger.setHost(host);
            }

            if (swagger.getSchemes() == null || (swagger.getSchemes() != null && swagger.getSchemes().isEmpty())) {
                String scheme = "";

                while (!scheme.matches("HTTP|HTTPS|WS|WSS")) {
                    scheme = JOptionPane.showInputDialog("`scheme` field is missing.\nPlease enter one below" + "" +
                                                                 ".\nAllowed values: HTTP, HTTPS, WS, WSS.");
                }
                swagger.addScheme(Scheme.valueOf(scheme));
            }

            String swaggerInfo = "Title: " + swagger.getInfo().getTitle() + " | " + "Version: " + swagger.getInfo()
                    .getVersion() + " | " + "Description: " + swagger.getInfo().getDescription();
            displayStatus(swaggerInfo, Color.BLACK);

            populateTable(swagger);
        } catch (Exception ex) {
            displayStatus("A fatal error occurred, please check the logs for further information", Color.RED);
            this.stderr.println(ex.toString());
        }
    }

    public JTable getTable() {
        return this.table;
    }

    public void displayStatus(String status, Color color) {
        for (Component component : this.statusPanel.getComponents()) {
            if (component instanceof JLabel) {
                ((JLabel) component).setText(status);
                component.setForeground(color);
            }
        }
    }

    private void populateTable(Swagger swagger) {
        DefaultTableModel defaultTableModel = (DefaultTableModel) this.table.getModel();
        List<io.swagger.models.Scheme> schemes = swagger.getSchemes();

        for (Scheme scheme : schemes) {
            for (Map.Entry<String, Path> path : swagger.getPaths().entrySet()) {
                for (Map.Entry<HttpMethod, Operation> operation : path.getValue().getOperationMap().entrySet()) {
                    StringBuilder stringBuilder = new StringBuilder();

                    for (Parameter parameter : operation.getValue().getParameters()) {
                        stringBuilder.append(parameter.getName()).append(", ");
                    }

                    if (stringBuilder.length() > 0) {
                        stringBuilder.setLength(stringBuilder.length() - 2);
                    }

                    defaultTableModel.addRow(new Object[]{defaultTableModel.getRowCount() + 1, operation.getKey()
                            .toString(), swagger.getHost().split(":")[0], scheme.toValue().toUpperCase(), swagger
                            .getBasePath(), path.getKey(), stringBuilder.toString()});

                    this.httpRequestResponses.add(new HttpRequestResponse(this.extensionHelper
                                                                                  .getBurpExtensionHelpers()
                                                                                  .buildHttpService(swagger.getHost()
                                                                                                            .split(":")[0], this.extensionHelper.getPort(swagger, scheme), this.extensionHelper.isUseHttps(scheme)), this.extensionHelper.isUseHttps(scheme), this.extensionHelper.buildRequest(swagger, path, operation)));

                    resizeTable(table);
                }
            }
        }
    }

    private void resizeTable(JTable table) {
        TableColumnModel columnModel = table.getColumnModel();

        for (int column = 0; column < table.getColumnCount(); column++) {
            int width = 16; // Min width

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
        return "Swagger Parser";
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
