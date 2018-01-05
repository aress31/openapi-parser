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
import swurg.utils.DataStructure;
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

    private String copyrightNotice = "Copyright \u00a9 2016 - 2018 Alexandre Teyar All Rights Reserved";

    private JLabel jLabelInfo = new JLabel(copyrightNotice);
    private JPanel jPanel;
    private JTable jTable;
    private JTextField jTextField;

    private List<HttpRequestResponse> httpRequestResponses = new ArrayList<>();
    private int rowIndex = 1;

    public Tab(IBurpExtenderCallbacks callbacks) {
        this.contextMenu = new ContextMenu(callbacks);
        this.extensionHelper = new ExtensionHelper(callbacks);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        // main container
        this.jPanel = new JPanel();
        this.jPanel.setLayout(new BorderLayout());
        this.jPanel.add(createJFilePanel(), BorderLayout.NORTH);
        this.jPanel.add(createJScrollTable());
        this.jPanel.add(createJInfoPanel(), BorderLayout.SOUTH);

        this.stdout.println("`Swagger Parser` tab created");
    }

    private JPanel createJFilePanel() {
        JPanel jPanel = new JPanel();

        this.jTextField = new JTextField(null, 48);
        this.jTextField.setEditable(true);

        JButton jButton = new JButton("Browse/Load");
        jButton.addActionListener(new ButtonListener());

        jPanel.add(new JLabel("Parse file/URL:"));
        jPanel.add(this.jTextField);
        jPanel.add(jButton);

        return jPanel;
    }

    private String browseForFile() {
        JFileChooser jFileChooser = new JFileChooser();
        String filepath;

        FileFilter filterJson = new FileNameExtensionFilter("Swagger JSON File (*.json)", "json");
        jFileChooser.addChoosableFileFilter(filterJson);
        FileFilter filterYml = new FileNameExtensionFilter("Swagger YAML File (*.yml, *.yaml)", "yaml", "yml");
        jFileChooser.addChoosableFileFilter(filterYml);

        jFileChooser.setFileFilter(filterYml);
        jFileChooser.setFileFilter(filterJson);

        if (jFileChooser.showOpenDialog(jPanel) == JFileChooser.APPROVE_OPTION) {
            File file = jFileChooser.getSelectedFile();
                
            filepath = file.getAbsolutePath();
            this.jTextField.setText(filepath);
        } else { filepath = null;}

        return filepath;
    }

    private void loadResource() {
        String resource = jTextField.getText();

        if (resource.isEmpty()) {
            resource = browseForFile();
            if (resource == null) {
                if (this.jLabelInfo.getForeground() == Color.RED) {
                    this.jLabelInfo.setForeground(Color.BLACK);
                    this.jLabelInfo.setText(this.copyrightNotice);
                }
                return;
            }
        } else {
            try {
                new URL(resource);
            } catch (MalformedURLException ex) {
                File file = new File(resource);

                if (!file.exists()) {        
                    resource = null;

                    this.jLabelInfo.setForeground(Color.RED);
                    this.jLabelInfo.setText("File does not exist! Enter the full path to the file, or a valid URL.");
                    this.jTextField.requestFocus();
                    this.jTextField.selectAll();

                    return;
                }
            }
        }

        this.jLabelInfo.setForeground(Color.BLACK);
        this.jLabelInfo.setText(null);

        try {
            Loader loader = new Loader();
            Swagger swagger = loader.process(resource);

            // add regex validation
            if (swagger.getHost() == null || (swagger.getHost() != null && swagger.getHost().isEmpty())) {
                String host = JOptionPane.showInputDialog("`host` field is missing.\nPlease enter one below.\nFormat:" +
                                                                  " <host> or <host:port>");
                swagger.setHost(host);
            }

            if (swagger.getSchemes() == null || (swagger.getSchemes() != null && swagger.getSchemes().isEmpty())) {
                String scheme = "";

                while (!scheme.matches("HTTP|HTTPS|WS|WSS")) {
                    scheme = JOptionPane.showInputDialog("`scheme` field is missing.\nPlease enter one below" +
                                                                 ".\nAllowed values: HTTP, HTTPS, WS, WSS.");
                }
                swagger.addScheme(Scheme.valueOf(scheme));
            }

            String infoText = "Title: " + swagger.getInfo().getTitle() + " | " +
                    "Version: " + swagger.getInfo().getVersion() + " | " +
                    "Description: " + swagger.getInfo().getDescription();

            this.jLabelInfo.setForeground(Color.BLACK);
            this.jLabelInfo.setText(infoText);

            createJTable(swagger);
        } catch (Exception ex) {
            this.stderr.println(ex.toString());

            this.jLabelInfo.setForeground(Color.RED);
            this.jLabelInfo.setText("A fatal error occurred, please check the logs for further information");
        }

    }

    @SuppressWarnings("serial")
    private JScrollPane createJScrollTable() {
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
        this.jTable = new JTable(new DefaultTableModel(rows, columns) {
            @Override
            public boolean isCellEditable(int rows, int columns) {
                return false;
            }
        });

        this.jTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                int selectedRow = jTable.rowAtPoint(e.getPoint());

                if (selectedRow >= 0 && selectedRow < jTable.getRowCount()) {
                    if (!jTable.getSelectionModel().isSelectedIndex(selectedRow)) {
                        jTable.setRowSelectionInterval(selectedRow, selectedRow);
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
                DataStructure dataStructure = new DataStructure(
                        jTable,
                        httpRequestResponses,
                        jTextField,
                        jLabelInfo
                );

                contextMenu.setDataStructure(dataStructure);
                contextMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        return new JScrollPane(this.jTable);
    }

    private void createJTable(Swagger swagger) {
        DefaultTableModel model = (DefaultTableModel) this.jTable.getModel();
        List<io.swagger.models.Scheme> schemes = swagger.getSchemes();

        for (io.swagger.models.Scheme scheme : schemes) {
            for (Map.Entry<String, Path> path : swagger.getPaths().entrySet()) {
                for (Map.Entry<HttpMethod, Operation> operation : path.getValue().getOperationMap().entrySet()) {
                    StringBuilder stringBuilder = new StringBuilder();

                    for (Parameter parameter : operation.getValue().getParameters()) {
                        stringBuilder.append(parameter.getName()).append(", ");
                    }

                    if (stringBuilder.length() > 0) {
                        stringBuilder.setLength(stringBuilder.length() - 2);
                    }

                    model.addRow(
                            new Object[]{
                                    this.rowIndex,
                                    operation.getKey().toString(),
                                    swagger.getHost().split(":")[0],
                                    scheme.toValue().toUpperCase(),
                                    swagger.getBasePath(),
                                    path.getKey(),
                                    stringBuilder.toString()
                            }
                    );

                    this.httpRequestResponses.add(
                            new HttpRequestResponse(
                                    this.extensionHelper.getBurpExtensionHelpers().buildHttpService(
                                            swagger.getHost().split(":")[0],
                                            this.extensionHelper.getPort(swagger, scheme),
                                            this.extensionHelper.isUseHttps(scheme)
                                    ),
                                    this.extensionHelper.isUseHttps(scheme),
                                    this.extensionHelper.buildRequest(swagger, path, operation)
                            )
                    );

                    resizeColumnWidth(jTable);
                    this.rowIndex++;
                }
            }
        }
    }

    private void resizeColumnWidth(JTable table) {
        final TableColumnModel columnModel = table.getColumnModel();

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

    private JPanel createJInfoPanel() {
        JPanel jPanelInfo = new JPanel();
        jPanelInfo.add(this.jLabelInfo);

        return jPanelInfo;
    }

    @Override
    public Component getUiComponent() {
        return this.jPanel;
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
                loadResource();
            }
        }
    }
}
