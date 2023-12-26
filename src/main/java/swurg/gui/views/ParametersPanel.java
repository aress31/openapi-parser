package swurg.gui.views;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Frame;

import java.awt.event.ItemEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

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
import swurg.observers.TableModelObserver;
import swurg.utilities.HtmlResourceLoader;

public class ParametersPanel extends JPanel
        implements HttpHandler, TableModelObserver {

    private final Frame suiteFrame;

    private final ParametersTableModel parametersTableModel;

    private final List<ToolType> toolsInScope = new ArrayList<>();
    private final List<ToolType> toolsMap = List.of(
            ToolType.EXTENSIONS,
            ToolType.INTRUDER,
            ToolType.PROXY,
            ToolType.REPEATER,
            ToolType.SCANNER,
            ToolType.SEQUENCER,
            ToolType.TARGET);

    private JScrollPane scrollPane;

    public ParametersPanel(MontoyaApi montoyaApi) {
        this.suiteFrame = montoyaApi.userInterface().swingUtils().suiteFrame();

        this.parametersTableModel = new ParametersTableModel();

        initComponents();
        addComponentListeners();
    }

    private void addComponentListeners() {
        this.addComponentListener(new ComponentAdapter() {
            private void setScrollPanePreferredSize() {
                int newWidth = (int) (suiteFrame.getWidth() * 0.25);
                int newHeight = suiteFrame.getHeight() - 210;

                scrollPane.setPreferredSize(new Dimension(newWidth, newHeight));
            }

            @Override
            public void componentResized(ComponentEvent e) {
                setScrollPanePreferredSize();
            }

            @Override
            public void componentShown(ComponentEvent e) {
                setScrollPanePreferredSize();
            }
        });
    }

    private void initComponents() {
        this.setLayout(new BorderLayout());

        TablePanel tablePanel = new TablePanel(parametersTableModel, new CustomTableCellRenderer());
        ParametersContextMenu contextMenu = new ParametersContextMenu(tablePanel.getTable());
        tablePanel.setContextMenu(contextMenu);

        this.add(createNorthPanel(), BorderLayout.NORTH);
        this.add(tablePanel, BorderLayout.CENTER);
        this.add(createEastPanel(), BorderLayout.EAST);
        this.add(new StatusPanel(), BorderLayout.SOUTH);
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
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder("How To"));

        this.scrollPane = new JScrollPane(createEditorPane("howTo.html"));
        this.scrollPane.setBorder(null);

        panel.add(this.scrollPane);

        return panel;
    }

    private JEditorPane createEditorPane(String resourcePath) {
        String htmlContent = HtmlResourceLoader.loadHtmlContent(resourcePath);

        JEditorPane editorPane = new JEditorPane();
        editorPane.setContentType("text/html");
        editorPane.setText(htmlContent);
        editorPane.setEditable(false);

        return editorPane;
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
                    this.parametersTableModel.getMyHttpParameters());
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

    @Override
    public void onMyHttpRequestsUpdate(int event, List<MyHttpRequest> myHttpRequests) {
        Set<MyHttpParameter> myHttpParameters = myHttpRequests.stream()
                .flatMap(myHttpRequest -> myHttpRequest.getHttpRequest().parameters().stream()
                        .map(myHttpParameter -> MyHttpParameter.builder()
                                .httpParameter(HttpParameter.parameter(myHttpParameter.name(), myHttpParameter.value(),
                                        myHttpParameter.type()))
                                .build()))
                .collect(Collectors.toSet());

        parametersTableModel.setMyHttpParameters(myHttpParameters);
    }
}
