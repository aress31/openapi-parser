package swurg.gui;

import static burp.MyBurpExtension.COPYRIGHT;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import com.google.common.base.Strings;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolType;
import swurg.utilities.DataModel;

import burp.api.montoya.MontoyaApi;

import swurg.utilities.RequestWithMetadata;

public class ParametersPanel extends JPanel
        implements HttpHandler {

    private Logging logging;

    private transient List<HttpParameter> editedParameters = new ArrayList<>();
    private transient List<HttpParameter> parameters = new ArrayList<>();
    private transient List<ToolType> toolsInScope = new ArrayList<>();
    private transient TableRowSorter<TableModel> tableRowSorter;

    private JTable table;
    private JTextField filterTextField = new JTextField(null, 32);

    private Map<String, ToolType> toolsMap = Map.of("Extensions", ToolType.EXTENSIONS, "Intruder",
            ToolType.INTRUDER, "Proxy", ToolType.PROXY, "Repeater",
            ToolType.REPEATER, "Scanner", ToolType.SCANNER, "Sequencer",
            ToolType.SEQUENCER, "Target",
            ToolType.TARGET);

    private DataModel parserModel;

    public ParametersPanel(MontoyaApi montoyaApi, DataModel parserModel) {
        this.logging = montoyaApi.logging();

        initComponents();

        // parserModel.addPropertyChangeListener(new PropertyChangeListener() {
        // @Override
        // public void propertyChange(PropertyChangeEvent evt) {
        // logging.logToOutput("public void propertyChange(PropertyChangeEvent evt)");

        // resetParametersList((DefaultTableModel) table.getModel());

        // if (!parserModel.getLogEntries().isEmpty()) {
        // populateTableWithData((DefaultTableModel) table.getModel(),
        // parserModel.getLogEntries());
        // }
        // }
        // });

        this.parserModel = parserModel;
    }

    public void updateParserModel(DataModel dataModel) {
        this.parserModel = dataModel;
        // Perform any necessary updates to the UI based on the new dataModel
    }

    // Clear the parameters list and reset the table dataModel
    private void resetParametersList(DefaultTableModel tableModel) {
        parameters.clear();
        editedParameters.clear();

        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
        });
    }

    private void populateTableWithData(DefaultTableModel tableModel, List<RequestWithMetadata> logEntries) {
        for (RequestWithMetadata logEntry : logEntries) {
            HttpRequest httpRequest = logEntry.getHttpRequest();

            for (HttpParameter httpParameter : httpRequest.parameters()) {
                if (!rowExists(tableModel, httpParameter)) {
                    SwingUtilities.invokeLater(() -> {
                        tableModel.addRow(new Object[] { tableModel.getRowCount(), httpParameter.name(),
                                httpParameter.type().name(),
                                httpParameter.value(), "" });
                    });
                }
            }
        }
    }

    private boolean rowExists(DefaultTableModel tableModel, HttpParameter httpParameter) {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            if (tableModel.getValueAt(i, 1).equals(httpParameter.type().name()) &&
                    tableModel.getValueAt(i, 2).equals(httpParameter.value())) {
                return true;
            }
        }

        return false;
    }

    private void initComponents() {
        this.setLayout(new BorderLayout());

        JPanel tablePanel = initTablePanel();
        JPanel scopePanel = initScopePanel();
        JPanel howToPanel = initHowToPanel();

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, howToPanel);
        splitPane.setResizeWeight(0.75);

        // Use ComponentAdapter instead of ComponentListener to simplify the code
        this.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                splitPane.setDividerLocation(0.75);
                // Remove the listener once the divider location is set
                removeComponentListener(this);
            }
        });

        JPanel southPanel = new JPanel();
        JLabel copyrightLabel = new JLabel(COPYRIGHT);
        copyrightLabel.putClientProperty("html.disable", null);
        southPanel.add(copyrightLabel);

        this.add(scopePanel, BorderLayout.NORTH);
        this.add(splitPane);
        this.add(southPanel, BorderLayout.SOUTH);
    }

    public JPanel initScopePanel() {
        JPanel scopePanel = new JPanel();
        scopePanel.setBorder(BorderFactory.createTitledBorder("Match/Replace Scope"));

        for (Map.Entry<String, ToolType> tool : toolsMap.entrySet()) {
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

        return scopePanel;
    }

    public JPanel initHowToPanel() {
        JLabel howToLabel = new JLabel("<html>" + "<body style=\"text-align: justify; text-justify: inter-word;\">"
                + "<p>This tab enables the visualization and editing of detected parameters (including their parsed types/values) within parsed OpenAPI files (found in the 'Parser' tab).</p>"
                + "<br/>"
                + "<p>To effectively use the match and replace feature when assessing OpenAPI-based RESTful APIs, set valid test values in the 'Edited Value' column. The match and replace will only be applied to requests that meet all of the following conditions:</p>"
                + "<ul>"
                + "<li>The BurpSuite tool to monitor/process is selected in the 'Match/Replace Scope' section of this tab.</li>"
                + "<li>The request contains at least one parameter with its name and type matching 'Parameter' and 'Type', and its value matching 'Parsed Value'.</li>"
                + "</ul>"
                + "<p>For optimal results and accuracy, fill the 'Edited Value' column with valid test parameters (i.e., those that trigger an HTTP 200 response) before launching any scans.</p>"
                + "<br/>"
                + "<p><u>Warning:</u> Operations in the 'Parser' tab, such as clicking 'Clear item(s)' or 'Clear all' options in the contextual menu, or clicking the 'Browse/Load' button, will reset the 'Parameters' tab.</p>"
                + "<ul>" + "<li>Any click on the 'Clear item(s)' or 'Clear all' options of the contextual menu.</li>"
                + "<li>Any click on the 'Browse/Load' button.</li>" + "</ul>"
                + "<p><u>Known bugs <b>(PRs are welcome)</b>:</u></p>" + "<ul>"
                + "<li>Body parameters can only be formatted as 'application/x-www-form-urlencoded' due to current Burp Extender API limitations.</li>"
                + "<li>Editing the 'Edited Value' column in the 'Parameters' tab while filtering the table may result in the edited value being set to 'null'.</li>"
                + "<li>Deep/recursive parsing of OpenAPI Schema fields is not supported.</li>" + "</ul>"
                + "</body>" + "</html>");
        howToLabel.putClientProperty("html.disable", null);

        JPanel howToPanel = new JPanel(new GridBagLayout());
        howToPanel.setBorder(BorderFactory.createTitledBorder("How To"));

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.insets = new Insets(4, 8, 4, 8);
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;

        howToPanel.add(howToLabel, gridBagConstraints);

        return howToPanel;
    }

    public JPanel initTablePanel() {
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

        this.table = new JTable();

        Object[] columns = { "#", "Parameter", "Type",
                "Parsed Value (Data type or Example Value)", "Edited Value" };
        Object[][] rows = {};

        this.table.setModel(new DefaultTableModel(rows, columns) {
            @Override
            public boolean isCellEditable(int rows, int columns) {
                return columns == 4;
            }
        });

        // this.table.getModel().addTableModelListener((TableModelListener) new
        // TableModelListener() {
        // @Override
        // public void tableChanged(TableModelEvent e) {
        // if (e.getType() == TableModelEvent.UPDATE) {
        // String name = table.getValueAt(e.getFirstRow(), 1).toString();
        // String type = table.getValueAt(e.getFirstRow(), 2).toString();
        // String value = table.getValueAt(e.getFirstRow(), 3).toString();

        // if (value != null && !value.isBlank()) {
        // editedParameters.removeIf(x -> x.name().equals(name) && x.getType() == (byte)
        // type);
        // editedParameters.add(callbacks.getHelpers().buildParameter(name, value,
        // (byte) type));
        // } else {
        // editedParameters.removeIf(x -> x.getName().equals(name) && x.getType() ==
        // (byte) type);
        // }
        // }
        // }
        // });

        this.table.setAutoCreateRowSorter(true);
        this.tableRowSorter = new TableRowSorter<>(this.table.getModel());
        this.table.setRowSorter(this.tableRowSorter);

        JPanel filterPanel = new JPanel();
        filterPanel.add(new JLabel("Filter (accepts regular expressions):"));
        // Prevents JTextField from collapsing on resizes...
        this.filterTextField.setMinimumSize(new Dimension(this.filterTextField.getPreferredSize()));
        filterPanel.add(this.filterTextField);

        JPanel tablePanel = new JPanel(new GridBagLayout());

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
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

        tablePanel.add(new JScrollPane(this.table), gridBagConstraints);

        return tablePanel;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        Annotations annotations = httpRequestToBeSent.annotations();
        HttpRequest updatedHttpRequest = httpRequestToBeSent;

        for (ToolType toolInScope : toolsInScope) {
            if (httpRequestToBeSent.toolSource().isFromTool(toolInScope)) {
                updatedHttpRequest = updateRequestParameters(httpRequestToBeSent);
            }
        }

        // Return the modified request to Burp with updated annotations.
        return RequestToBeSentAction.continueWith(updatedHttpRequest, annotations);
    }

    private HttpRequest updateRequestParameters(HttpRequestToBeSent httpRequestToBeSent) {
        HttpRequest updatedHttpRequest = httpRequestToBeSent;

        for (HttpParameter httpParameterToBeSent : httpRequestToBeSent.parameters()) {
            logging.logToOutput(
                    "[*] Processing: " + httpParameterToBeSent.name() + " " + httpParameterToBeSent.type() + " "
                            + httpParameterToBeSent.value());

            for (HttpParameter httpParameter : this.parameters) {
                if (isMatchingParameter(httpParameterToBeSent, httpParameter)) {
                    logging.logToOutput("[+] Match: " + httpParameter.name() + " " + httpParameter.type() + " "
                            + httpParameter.value());

                    // Modify the request by adding url param.
                    updatedHttpRequest = httpRequestToBeSent.withUpdatedParameters(httpParameter);
                    break;
                }
            }
        }

        return updatedHttpRequest;
    }

    private boolean isMatchingParameter(HttpParameter httpParameterToBeSent, HttpParameter httpParameter) {
        return httpParameterToBeSent.name().equals(httpParameter.name())
                && httpParameterToBeSent.type().name() == httpParameter.type().name()
                && httpParameterToBeSent.value().equals(httpParameter.value());
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'handleHttpResponseReceived'");
    }
}
