package swurg.gui.views;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import burp.api.montoya.logging.Logging;
import burp.http.MyHttpParameter;
import burp.http.MyHttpRequest;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.core.ToolType;

import burp.api.montoya.MontoyaApi;
import swurg.gui.components.StatusPanel;
import swurg.gui.components.menus.ParametersContextMenu;
import swurg.gui.components.tables.TablePanel;
import swurg.gui.components.tables.models.ParametersTableModel;
import swurg.gui.components.tables.renderers.CustomTableCellRenderer;
import swurg.observers.ParametersPanelObserver;
import swurg.utilities.HtmlResourceLoader;

public class ParametersPanel extends JPanel
        implements HttpHandler, ParametersPanelObserver {

    private Logging logging;

    private transient List<ToolType> toolsInScope = new ArrayList<>();

    private ParametersTableModel parametersTableModel;

    private List<ToolType> toolsMap = List.of(
            ToolType.EXTENSIONS,
            ToolType.INTRUDER,
            ToolType.PROXY,
            ToolType.REPEATER,
            ToolType.SCANNER,
            ToolType.SEQUENCER,
            ToolType.TARGET);

    private List<MyHttpRequest> myHttpRequests;

    public ParametersPanel(MontoyaApi montoyaApi, List<MyHttpRequest> myHttpRequests) {
        this.logging = montoyaApi.logging();
        this.myHttpRequests = myHttpRequests;

        parametersTableModel = ParametersTableModel.fromRequestWithMetadataList(myHttpRequests);

        initComponents();
    }

    @Override
    public void onRequestWithMetadatasUpdate() {
        parametersTableModel.updateData(myHttpRequests);

    }

    private void initComponents() {
        setLayout(new BorderLayout());

        JPanel northPanel = createNorthPanel();
        TablePanel tablePanel = new TablePanel(parametersTableModel, new CustomTableCellRenderer());
        ParametersContextMenu contextMenu = new ParametersContextMenu(tablePanel.getTable());
        tablePanel.setContextMenu(contextMenu);
        JPanel eastPanel = createEastPanel();
        JPanel southPanel = new StatusPanel();

        add(northPanel, BorderLayout.NORTH);
        add(southPanel, BorderLayout.SOUTH);

        // add a nested JPanel with a GridBagLayout to the CENTER of the main container
        JPanel centerContainer = new JPanel(new GridBagLayout());
        add(centerContainer, BorderLayout.CENTER);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 0.75;
        gbc.weighty = 1.0;
        centerContainer.add(tablePanel, gbc);

        gbc.gridx = 3;
        gbc.gridwidth = 1;
        gbc.weightx = 0.25;
        centerContainer.add(eastPanel, gbc);

        // set the preferred sizes of the center and east panels
        tablePanel.setPreferredSize(new Dimension(0, 0));
        eastPanel.setPreferredSize(new Dimension(0, 0));
    }

    private JPanel createNorthPanel() {
        JPanel northPanel = new JPanel();
        northPanel.setBorder(BorderFactory.createTitledBorder("Match/Replace Scope"));

        toolsMap.forEach(tool -> {
            JCheckBox checkBox = new JCheckBox(tool.name());
            checkBox.setSelected(tool.equals(ToolType.PROXY) || tool.equals(ToolType.REPEATER));

            if (checkBox.isSelected())
                toolsInScope.add(tool);

            checkBox.addItemListener(e -> {
                if (e.getStateChange() == ItemEvent.SELECTED)
                    toolsInScope.add(tool);
                else
                    toolsInScope.remove(tool);
            });

            northPanel.add(checkBox);
        });

        return northPanel;
    }

    private JPanel createEastPanel() {
        String htmlContent = HtmlResourceLoader.loadHtmlContent("howToText.html");
        JLabel label = new JLabel(htmlContent);
        label.putClientProperty("html.disable", null);

        JPanel eastPanel = new JPanel(new GridBagLayout());
        eastPanel.setBorder(BorderFactory.createTitledBorder("How To"));

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.insets = new Insets(4, 8, 4, 8);
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;

        eastPanel.add(label, gridBagConstraints);

        return eastPanel;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        if (!httpRequestToBeSent.hasParameters()) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }

        ToolType matchingTool = toolsInScope.stream()
                .filter(toolInScope -> httpRequestToBeSent.toolSource().isFromTool(toolInScope))
                .findFirst()
                .orElse(null);

        if (matchingTool != null) {
            HttpRequest updatedHttpRequest = updateHttpRequestToBeSent(httpRequestToBeSent,
                    this.parametersTableModel.getHttpParameters());
            return RequestToBeSentAction.continueWith(updatedHttpRequest);
        }

        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    private HttpRequest updateHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent,
            Set<MyHttpParameter> tableParameters) {
        List<ParsedHttpParameter> parsedParametersToBeSent = httpRequestToBeSent.parameters();
        List<HttpParameter> updatedParameters = new ArrayList<>();

        parsedParametersToBeSent.forEach(parsedParameterToBeSent -> {
            HttpParameter parameterToBeSent = HttpParameter.parameter(
                    parsedParameterToBeSent.name(),
                    parsedParameterToBeSent.value(),
                    parsedParameterToBeSent.type());

            tableParameters.stream()
                    .filter(tableHttpParameter -> parameterToBeSent.equals(tableHttpParameter.getHttpParameter())
                            && tableHttpParameter.getEditedValue() != null)
                    .findFirst()
                    .ifPresent(tableParameter -> {
                        HttpParameter updatedParameter = HttpParameter.parameter(
                                parameterToBeSent.name(),
                                tableParameter.getEditedValue(),
                                parameterToBeSent.type());
                        updatedParameters.add(updatedParameter);
                    });
        });

        return httpRequestToBeSent.withUpdatedParameters(updatedParameters);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
