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

package burp;

import com.google.gson.Gson;
import com.google.gson.JsonElement;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import java.io.BufferedReader; 
import java.io.File; 
import java.io.FileReader; 
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;

import java.util.ArrayList;
import java.util.Map;
import java.util.List;

public class Tab implements ITab {
    private Helper helper = new Helper();
    private PrintWriter stderr;

    private ContextMenu contextMenu;
    private JLabel infoLabel;
    private JPanel container;
    private JTable table;
    private JTextField fileTextField;

    private int rowIndex = 1;

    private List<HttpRequest> httpRequests;

    public Tab(IBurpExtenderCallbacks callbacks) {
        contextMenu = new ContextMenu(callbacks);
        httpRequests = new ArrayList<HttpRequest>();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // main container
        container = new JPanel();
        container.setLayout(new BorderLayout());
        container.add(drawJFilePanel(), BorderLayout.NORTH);
        container.add(drawJScrollTable());
        container.add(drawJInfoPanel(), BorderLayout.SOUTH);
    }

    private JPanel drawJFilePanel() {
        JPanel panel = new JPanel();
        JLabel label = new JLabel("Parse file:");
        fileTextField = new JTextField("", 48);
        JButton button = new JButton("File");

        fileTextField.setEditable(false);
        button.addActionListener(new ButtonListener());

        panel.add(label);
        panel.add(fileTextField);
        panel.add(button);

        return panel;
    }

    class ButtonListener implements ActionListener {
        ButtonListener() {
            super();
        }

        public void actionPerformed (ActionEvent e) {
            if (e.getSource() instanceof JButton) {
                processFile();
            }
        }
    }

    private void processFile() {
        JFileChooser fileChooser = new JFileChooser();
        FileFilter filter = new FileNameExtensionFilter("Swagger File (*.json)", "json");
        fileChooser.addChoosableFileFilter(filter);
        fileChooser.setFileFilter(filter);

        int result = fileChooser.showOpenDialog(container);

        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            fileTextField.setText(file.getName());
            infoLabel.setForeground(Color.BLACK);
            infoLabel.setText(null);

            try {
                Gson gson = new Gson();
                BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
                RESTful api = gson.fromJson(bufferedReader, RESTful.class);
                String infoText = "Title: " + api.getInfo().getTitle() + " | " +
                    "Version: " + api.getInfo().getVersion()  + " | " +
                    "Swagger Version: " + api.getSwaggerVersion();

                infoLabel.setForeground(Color.BLACK);
                infoLabel.setText(infoText);

                populateJTable(api);
            } catch (Exception ex) {
                StringWriter stringWriter = new StringWriter();
                ex.printStackTrace(new PrintWriter(stringWriter));
                stderr.println(stringWriter.toString());

                infoLabel.setForeground(Color.RED);
                infoLabel.setText("A fatal error occured, please check the logs for further information");
            }
        } 
    }

    @SuppressWarnings("serial")
    private JScrollPane drawJScrollTable() {
        Object columns[] = {
            "#",
            "Method", 
            "Host",
            "Protocol",
            "Base Path",
            "Endpoint",
            "Params"
        };
        Object rows[][] = {};
        table = new JTable(new DefaultTableModel(rows, columns) {
            @Override
            public boolean isCellEditable(int rows, int columns) {
               return false;
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);

        table.setSelectionForeground(Color.BLACK);
        table.addMouseListener(new MouseAdapter() {         
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

            private void show(MouseEvent e) {
                DataStructure data = new DataStructure(
                    table, 
                    httpRequests,
                    fileTextField,
                    infoLabel
                );
            
                contextMenu.setDataStructure(data);
                contextMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        return scrollPane;
    }

    public void resizeColumnWidth(JTable table) {
        final TableColumnModel columnModel = table.getColumnModel();

        for (int column = 0; column < table.getColumnCount(); column++) {
            int width = 16; // Min width

            for (int row = 0; row < table.getRowCount(); row++) {
                TableCellRenderer renderer = table.getCellRenderer(row, column);
                Component comp = table.prepareRenderer(renderer, row, column);
                width = Math.max(comp.getPreferredSize().width +1 , width);
            }

            if(width > 300) {
                width = 300;
            }

            columnModel.getColumn(column).setPreferredWidth(width);
        }
    }

    private void populateJTable(RESTful api) {
        Gson gson = new Gson();
        DefaultTableModel model = (DefaultTableModel) table.getModel();
        ArrayList<Scheme> schemes = helper.buildSchemes(api);

        if (schemes.isEmpty()) {
            infoLabel.setForeground(Color.RED);
            infoLabel.setText("Invalid Swagger format detected, please ensure that the `schemes` is completed or the `host` has a port number");            
        }

        for (Scheme scheme: schemes) {
            String basePath = api.getBasePath();
            String host = helper.validateHostSyntax(api.getHost());

            for (Map.Entry<String, JsonElement> path: api.getPaths().entrySet()) {
                String endpoint = path.getKey();
                String url = basePath + endpoint;

                for (Map.Entry<String, JsonElement> entry: path.getValue().getAsJsonObject().entrySet()) {
                    Path call = gson.fromJson(entry.getValue(), Path.class);
                    String httpMethod = entry.getKey().toUpperCase();
                    call.setType(httpMethod);

                    model.addRow(new Object[] {
                            rowIndex,
                            httpMethod,
                            host,
                            scheme.getProtocol(), 
                            basePath, 
                            endpoint,
                            helper.parseParams(call.getParameters())
                        }
                    );

                    resizeColumnWidth(table);

                    helper.populateHttpRequests(httpRequests, httpMethod, url, host, scheme.getPort(), scheme.getEncryption(), call.getParameters(), 
                        api.getDefinitions(), call.getConsumes(), call.getProduces());

                    rowIndex++;
                }
            }
        }
    }

    private JPanel drawJInfoPanel() {
        JPanel panel = new JPanel();
        infoLabel = new JLabel("Copyright \u00a9 2016 Alexandre Teyar All Rights Reserved");

        panel.add(infoLabel);

        return panel;
    }

    @Override
    public Component getUiComponent() {
        return container;
    }

    @Override
    public String getTabCaption() {
        return "Swagger Parser";
    }
}