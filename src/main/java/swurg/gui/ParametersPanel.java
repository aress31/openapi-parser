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
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
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
        filterPanel.add(this.filterTextField);

        JPanel howToPanel = new JPanel();
        howToPanel.setBorder(BorderFactory.createTitledBorder("How To"));
        JLabel howToLabel = new JLabel("<html>"
                + "<p>This tab allows for the visualisation/edition of the detected parameters (along with their parsed 'types/values') within<br/>parsed OpenAPI file(s) ('Parser' tab).<p/>"
                + "<p>One of the ways to leverage this match and replace feature when assessing OpenAPI based RESTful API(s) is to set"
                + "<br/>" + "valid test values provided within the 'Edited Value' column.<p/>"
                + "<p>The match and replace will be applied only on request(s) with <b>ALL</b> of the following conditions met:</p>"
                + "<ul>"
                + "<li>The BurpSuite tool to monitor/process has been selected within the 'Match/Replace Scope' section of this tab.</li>"
                + "<li>The request(s) sent contain(s) at least a parameter with its 'name' and 'type' matching 'Parameter' and 'Type'"
                + "<br/>" + "<b>AND</b> its 'value' matching 'Parsed Value'.</li>" + "</ul>"
                + "<p>For optimals results/accuracy, it is strongly advised to take the time to properly fill the 'Edited Value' column with<br/>valid test parameters <em>(i.e., that would trigger an HTTP 200 response)</em> <b>PRIOR TO</b> launching any type of scan.</p>"
                + "<br/>"
                + "<p><u>Warning:</u> Currently, the following operations relevant to the 'Parser' tab would cause a total reset of the 'Parameters' tab:</p>"
                + "<ul>" + "<li>Any click on the 'Clear item(s)' or 'Clear all' options of the contextual menu.</li>"
                + "<li>Any click on the 'Browse/Load' button.</li>" + "</ul>"
                + "<p><u>Known bugs <b>(PRs are welcomed)</b>:</u></p>" + "<ul>"
                + "<li>Editing the 'Edited Value' column of the table in the 'Parameters' tab whilst filtering the"
                + "<br/>" + "table would cause the edited value to be set to 'null'.</li>"
                + "<li>No support for <b>deep/recursive</b> parsing of 'OpenAPI Schema fields'.</li>" + "</ul>"
                + "</html>");
        howToPanel.add(howToLabel);

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.add(filterPanel, BorderLayout.NORTH);
        tablePanel.add(new JScrollPane(this.parametersTable));

        JPanel southPanel = new JPanel();
        southPanel.add(this.statusLabel);

        this.add(scopePanel, BorderLayout.NORTH);
        this.add(tablePanel);
        this.add(howToPanel, BorderLayout.EAST);
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
