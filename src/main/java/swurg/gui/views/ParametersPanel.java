package swurg.gui.views;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.http.MyHttpParameter;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolType;

import burp.api.montoya.MontoyaApi;
import swurg.gui.components.StatusPanel;
import swurg.gui.components.menus.ParametersContextMenu;
import swurg.gui.components.tables.TablePanel;
import swurg.gui.components.tables.models.ParametersTableModel;
import swurg.gui.components.tables.renderers.CustomTableCellRenderer;
import swurg.observers.ParametersPanelObserver;
import swurg.utilities.HtmlResourceLoader;
import swurg.utilities.RequestWithMetadata;

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

    private List<RequestWithMetadata> requestWithMetadatas;

    public ParametersPanel(MontoyaApi montoyaApi, List<RequestWithMetadata> requestWithMetadatas) {
        this.logging = montoyaApi.logging();
        this.requestWithMetadatas = requestWithMetadatas;

        parametersTableModel = ParametersTableModel.fromRequestWithMetadataList(requestWithMetadatas);

        initComponents();
    }

    @Override
    public void onRequestWithMetadatasUpdate() {
        parametersTableModel.updateData(requestWithMetadatas);

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

        for (ToolType tool : toolsMap) {
            JCheckBox checkBox = new JCheckBox(tool.name());
            checkBox.setSelected(tool.equals(ToolType.PROXY) || tool.equals(ToolType.REPEATER));

            if (checkBox.isSelected()) {
                toolsInScope.add(tool);
            }

            checkBox.addItemListener(e -> {
                if (e.getStateChange() == ItemEvent.SELECTED) {
                    toolsInScope.add(tool);
                } else {
                    toolsInScope.remove(tool);
                }
            });

            northPanel.add(checkBox);
        }

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
            for (MyHttpParameter httpParameter : this.parametersTableModel.getHttpParameters()) {
                if (shouldProcessParameter(httpParameterToBeSent, httpParameter)) {

                    MyHttpParameter editedParameter = new MyHttpParameter(httpParameterToBeSent);
                    editedParameter.setValue(httpParameter.getEditedValue());

                    updatedHttpRequest = updatedHttpRequest.withUpdatedParameters(editedParameter);
                    break;
                }
            }
        }

        return updatedHttpRequest;
    }

    private boolean shouldProcessParameter(HttpParameter httpParameterToBeSent, MyHttpParameter httpParameter) {
        return httpParameter.equals(httpParameterToBeSent) && httpParameter.getEditedValue() != null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        throw new UnsupportedOperationException("Unimplemented method 'handleHttpResponseReceived'");
    }
}
