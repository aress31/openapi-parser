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
#    limitations under the License. F
*/

package swurg.gui;

import static burp.BurpExtender.COPYRIGHT;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import com.google.common.base.Strings;

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IParameter;
import burp.IRequestInfo;
import burp.MessageEditorTab;
import swurg.utilities.LogEntry;

public class ParametersPanel extends JPanel implements IHttpListener, IMessageEditorTabFactory {

    private transient IBurpExtenderCallbacks callbacks;

    private JLabel statusLabel = new JLabel(COPYRIGHT);
    private JTable parametersTable;
    private JTextField filterTextField = new JTextField(null, 32);

    private transient List<IParameter> parameters = new ArrayList<>();
    private transient List<IParameter> editedParameters = new ArrayList<>();
    private transient List<Integer> toolsInScope = new ArrayList<>();

    private transient TableRowSorter<TableModel> tableRowSorter;

    private Map<String, Integer> toolsMap = Map.of("Extender", IBurpExtenderCallbacks.TOOL_EXTENDER, "Intruder",
            IBurpExtenderCallbacks.TOOL_INTRUDER, "Proxy", IBurpExtenderCallbacks.TOOL_PROXY, "Repeater",
            IBurpExtenderCallbacks.TOOL_REPEATER, "Scanner", IBurpExtenderCallbacks.TOOL_SCANNER, "Sequencer",
            IBurpExtenderCallbacks.TOOL_SEQUENCER, "Spider", IBurpExtenderCallbacks.TOOL_SPIDER, "Target",
            IBurpExtenderCallbacks.TOOL_TARGET);

    private Model model;

    Boolean enableMessageEditorTab;
    private IHttpRequestResponse interceptedRequestResponse;
    MessageEditorTab messageEditorTab;

    public ParametersPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.messageEditorTab = new MessageEditorTab(callbacks);

        initComponents();
    }

    public void setModel(Model model) {
        model.addPropertyChangeListener(new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (!model.getLogEntries().isEmpty()) {
                    // Note: Dirty workaround to avoide table diplicates
                    parameters.clear();
                    editedParameters.clear();
                    ((DefaultTableModel) parametersTable.getModel()).setRowCount(0);
                    initParametersList();
                }
            }
        });

        this.model = model;
    }

    private void initComponents() {
        this.setLayout(new BorderLayout());

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

        this.parametersTable = new JTable();

        Object[] columns = { "Parameter", "Type (0: inQuery, 1: inBody)", "Parsed Value", "Edited Value" };
        Object[][] rows = {};

        this.parametersTable.setModel(new DefaultTableModel(rows, columns) {
            @Override
            public Class<?> getColumnClass(int column) {
                if (column == 1) {
                    return Integer.class;
                }

                return super.getColumnClass(column);
            }

            @Override
            public boolean isCellEditable(int rows, int columns) {
                return columns == 3;
            }
        });

        this.parametersTable.getModel().addTableModelListener((TableModelListener) new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                if (e.getType() == TableModelEvent.UPDATE) {
                    String name = (String) parametersTable.getValueAt(e.getFirstRow(), 0);
                    int type = Integer.parseInt(parametersTable.getValueAt(e.getFirstRow(), 1).toString());
                    String value = (String) parametersTable.getValueAt(e.getFirstRow(), 3);

                    if (value != null && !value.isBlank()) {
                        editedParameters.removeIf(x -> x.getName().equals(name) && x.getType() == (byte) type);
                        editedParameters.add(callbacks.getHelpers().buildParameter(name, value, (byte) type));
                    } else {
                        editedParameters.removeIf(x -> x.getName().equals(name) && x.getType() == (byte) type);
                    }
                }
            }
        });

        this.parametersTable.setAutoCreateRowSorter(true);
        this.tableRowSorter = new TableRowSorter<>(this.parametersTable.getModel());
        this.parametersTable.setRowSorter(this.tableRowSorter);

        JPanel scopePanel = new JPanel();
        scopePanel.setBorder(BorderFactory.createTitledBorder("Match/Replace Scope"));

        for (Map.Entry<String, Integer> tool : toolsMap.entrySet()) {
            JCheckBox x = new JCheckBox(tool.getKey());

            if (List.of("Proxy", "Repeater").contains(tool.getKey())) {
                x.setSelected(true);
                this.toolsInScope.add(tool.getValue());
            }

            x.addItemListener((ItemListener) new ItemListener() {
                @Override
                public void itemStateChanged(ItemEvent e) {
                    if (e.getStateChange() == ItemEvent.SELECTED) {
                        toolsInScope.add(tool.getValue());
                    } else {
                        toolsInScope.remove(tool.getValue());
                    }
                }
            });

            scopePanel.add(x);
        }

        JPanel filterPanel = new JPanel();
        filterPanel.add(new JLabel("Filter (accepts regular expressions):"));
        // Prevents JTextField from collapsing on resizes...
        this.filterTextField.setMinimumSize(new Dimension(this.filterTextField.getPreferredSize()));
        filterPanel.add(this.filterTextField);

        JLabel howToLabel = new JLabel("<html>" + "<body style=\"text-align: justify; text-justify: inter-word;\">"
                + "<p>This tab allows for the visualisation/edition of the detected parameters (along with their parsed 'types/values') within parsed OpenAPI file(s) ('Parser' tab).</p>"
                + "<br/>"
                + "<p>One of the ways to leverage this match and replace feature when assessing OpenAPI based RESTful API(s) is to set"
                + "valid test values provided within the 'Edited Value' column.</p>" + "<br/>"
                + "<p>The match and replace will be applied only on request(s) with <b>ALL</b> of the following conditions met:</p>"
                + "<ul>"
                + "<li>The BurpSuite tool to monitor/process has been selected within the 'Match/Replace Scope' section of this tab.</li>"
                + "<li>The request(s) sent contain(s) at least a parameter with its 'name' and 'type' matching 'Parameter' and 'Type'"
                + "<b>AND</b> its 'value' matching 'Parsed Value'.</li>" + "</ul>"
                + "<p>For optimals results/accuracy, it is strongly advised to take the time to properly fill the 'Edited Value' column with valid test parameters <em>(i.e., that would trigger an HTTP 200 response)</em> <b>PRIOR TO</b> launching any type of scans.</p>"
                + "<br/>"
                + "<p><u>Warning:</u> Currently, the following operations relevant to the 'Parser' tab would cause a total reset of the 'Parameters' tab:</p>"
                + "<ul>" + "<li>Any click on the 'Clear item(s)' or 'Clear all' options of the contextual menu.</li>"
                + "<li>Any click on the 'Browse/Load' button.</li>" + "</ul>"
                + "<p><u>Known bugs <b>(PRs are welcomed)</b>:</u></p>" + "<ul>"
                + "<li>Body parameters can only be formatted as 'application/x-www-form-urlencoded', this is due"
                + "to the current limitations of the Burp Extender API.</li>"
                + "<li>Editing the 'Edited Value' column of the table in the 'Parameters' tab whilst filtering the"
                + "table would cause the edited value to be set to 'null'.</li>"
                + "<li>No support for <b>deep/recursive</b> parsing of 'OpenAPI Schema fields'.</li>" + "</ul>"
                + "</body>" + "</html>");

        JPanel howToPanel = new JPanel(new GridBagLayout());
        howToPanel.setBorder(BorderFactory.createTitledBorder("How To"));

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.insets = new Insets(4, 8, 4, 8);
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;

        howToPanel.add(howToLabel, gridBagConstraints);

        JLabel aboutLabel = new JLabel("<html>" + "<body style=\"text-align: justify; text-justify: inter-word;\">"
                + "<p>This extension has been developped by <b>Alexandre Teyar</b>, Managing Director at <b>Aegis Cyber</b>.</p>"
                + "<p>Extension version: <b>2.4.3</b></p>"
                + "<p>Do you have a feature request? Raise a ticket and share your thoughts.</p>"
                + "<p>Do you want to contribute to this project? PRs are welcome!</p>"
                + "<p>If you use and like this extension, show your appreciation by giving the Swurg repository a star and rating"
                + "this extension on BApp Store.</p>" + "<p>Special thanks to all the GitHub contributors!</p>"
                + "</body>" + "</html>");

        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new Insets(4, 4, 4, 4);
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;

        int index = 1;

        JPanel aboutButton = new JPanel(new GridBagLayout());

        for (Map.Entry<String, String> entry : Map.of("<html>Talk With <b>Aegis Cyber</b></html>",
                "www.aegiscyber.co.uk", "<html>Connect <b>(With Me)<b> on <b>LinkedIn</b></html>",
                "www.linkedin.com/in/alexandre-teyar", "<html>Follow <b>(Me)</b> on <b>GitHub</b></html>",
                "github.com/aress31", "<html>Submit <b>PR</b>/Report a <b>Bug</b></html>", "github.com/aress31/swurg")
                .entrySet()) {
            JButton x = new JButton();
            x.setPreferredSize(new Dimension(192, 34));
            x.setText(entry.getKey());
            x.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    try {
                        java.awt.Desktop.getDesktop().browse(new URI(entry.getValue()));
                    } catch (IOException | URISyntaxException e1) {
                        // Do nothing
                    }
                }
            });

            if (index % 2 == 0) {
                gridBagConstraints.gridx = 1;
            } else {
                gridBagConstraints.gridx = 0;
                gridBagConstraints.gridy++;
            }

            aboutButton.add(x, gridBagConstraints);

            index++;
        }

        JPanel aboutPanel = new JPanel(new GridBagLayout());
        aboutPanel.setBorder(BorderFactory.createTitledBorder("About"));

        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new Insets(4, 8, 4, 8);
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 0;

        aboutPanel.add(aboutLabel, gridBagConstraints);

        gridBagConstraints.gridy++;
        gridBagConstraints.fill = GridBagConstraints.NONE;
        gridBagConstraints.insets = new Insets(0, 4, 0, 4);
        gridBagConstraints.weightx = 0;
        gridBagConstraints.weighty = 1.0;

        aboutPanel.add(aboutButton, gridBagConstraints);

        aboutPanel.setPreferredSize(new Dimension(0, aboutPanel.getPreferredSize().height + 64));

        // JPanel eastPanel = new JPanel(new BorderLayout());
        // eastPanel.add(new JScrollPane(aboutPanel), BorderLayout.SOUTH);
        // eastPanel.add(howToPanel, BorderLayout.NORTH);

        JPanel tablePanel = new JPanel(new GridBagLayout());

        gridBagConstraints = new GridBagConstraints();

        gridBagConstraints.anchor = GridBagConstraints.LINE_START;
        gridBagConstraints.insets = new Insets(4, 0, 4, 0);
        gridBagConstraints.gridy = 0;
        gridBagConstraints.weightx = 0;
        gridBagConstraints.weighty = 0;

        tablePanel.add(filterPanel, gridBagConstraints);

        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.insets = new Insets(0, 0, 0, 0);
        gridBagConstraints.gridy++;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;

        tablePanel.add(new JScrollPane(this.parametersTable), gridBagConstraints);

        JPanel southPanel = new JPanel();
        southPanel.add(this.statusLabel);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setEnabled(false);
        splitPane.setTopComponent(tablePanel);
        splitPane.setBottomComponent(howToPanel);
        // splitPane.setBottomComponent(eastPanel);

        // Resize splitPane
        this.addComponentListener(new ComponentListener() {
            @Override
            public void componentResized(ComponentEvent e) {
                // Dummy comment
            }

            @Override
            public void componentMoved(ComponentEvent e) {
                // Dummy comment
            }

            @Override
            public void componentShown(ComponentEvent e) {
                splitPane.setDividerLocation(0.75);
                removeComponentListener(this);
            }

            @Override
            public void componentHidden(ComponentEvent e) {
                // Dummy comment
            }
        });

        this.add(scopePanel, BorderLayout.NORTH);
        this.add(splitPane);
        this.add(southPanel, BorderLayout.SOUTH);
    }

    public void initParametersList() {
        List<HttpRequestResponse> httpRequestResponses = this.model.getLogEntries().stream()
                .map(LogEntry::getHttpRequestResponse).collect(Collectors.toList());

        // Getting all the params
        for (HttpRequestResponse httpRequestResponse : httpRequestResponses) {
            IRequestInfo requestInfo = this.callbacks.getHelpers().analyzeRequest(httpRequestResponse.getHttpService(),
                    httpRequestResponse.getRequest());
            this.parameters.addAll(requestInfo.getParameters());
        }

        HashSet<Object> seen = new HashSet<>();
        this.parameters.removeIf(
                parameter -> !seen.add(List.of(parameter.getName(), parameter.getType(), parameter.getValue())));

        // Fill table
        for (IParameter parameter : this.parameters) {
            Object[] newRow = new Object[] { parameter.getName(), parameter.getType(), parameter.getValue(), null };

            ((DefaultTableModel) this.parametersTable.getModel()).addRow(newRow);
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        boolean isIntercepted = false;

        if (messageIsRequest && toolsInScope.contains(toolFlag)) {
            byte[] request = messageInfo.getRequest();

            for (IParameter editedParameter : this.editedParameters) {
                if (this.callbacks.getHelpers().getRequestParameter(request, editedParameter.getName()) != null) {
                    IParameter parsedParameter = this.parameters.stream()
                            .filter(p -> p.getName().equals(editedParameter.getName())
                                    && p.getType() == editedParameter.getType())
                            .findFirst().orElse(null);
                    IParameter requestParameter = this.callbacks.getHelpers().getRequestParameter(request,
                            editedParameter.getName());

                    if (requestParameter.getType() == editedParameter.getType()
                            && requestParameter.getValue().equals(parsedParameter.getValue())) {
                        request = this.callbacks.getHelpers().removeParameter(request, requestParameter);
                        request = this.callbacks.getHelpers().addParameter(request, editedParameter);

                        isIntercepted = true;
                    }
                }
            }

            messageInfo.setRequest(request);

            this.messageEditorTab.setIsEnabled(isIntercepted);
            // TODO: Workaround to common bug:
            // https://forum.portswigger.net/thread/repeater-tab-imessageeditortab-getmessage-ae1f0795
            this.messageEditorTab.setContent(messageInfo.getRequest());
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return messageEditorTab;
    }
}
