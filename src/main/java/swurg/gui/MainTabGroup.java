package swurg.gui;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTabbedPane;

import burp.api.montoya.MontoyaApi;
import swurg.gui.views.AboutPanel;
import swurg.gui.views.ParametersPanel;
import swurg.gui.views.ParserPanel;
import swurg.observers.ParserTableModelObserver;
import swurg.utilities.RequestWithMetadata;

import lombok.Data;

@Data
public class MainTabGroup extends JTabbedPane implements ParserTableModelObserver {

    private final transient MontoyaApi montoyaApi;

    private ParserPanel parserPanel;
    private ParametersPanel parametersPanel;
    private AboutPanel aboutPanel;

    List<RequestWithMetadata> requestWithMetadatas;

    public MainTabGroup(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        this.requestWithMetadatas = new ArrayList<>();

        initComponents();

        // Register this as an observer with the ParserTableModel
        parserPanel.getParserTableModel().registerObserver(this);
        parserPanel.getParserTableModel().registerParametersPanelObserver(parametersPanel);

    }

    private void initComponents() {
        parserPanel = new ParserPanel(montoyaApi, requestWithMetadatas);
        aboutPanel = new AboutPanel();
        parametersPanel = new ParametersPanel(montoyaApi, requestWithMetadatas);

        addTab("Parser", parserPanel);
        addTab("About", aboutPanel);
    }

    // Implement the onRequestWithMetadatasUpdate() method from the
    // ParserTableModelObserver interface
    @Override
    public void onRequestWithMetadatasUpdate() {
        // Check if ParametersPanel is not already added and requestWithMetadatas not
        // null
        if (indexOfComponent(parametersPanel) == -1 && !requestWithMetadatas.isEmpty()) {
            addTab("Parameters", parametersPanel);
        } else {
            if (indexOfComponent(parametersPanel) != -1 && requestWithMetadatas.isEmpty()) {
                removeTabAt(indexOfComponent(parametersPanel));
            }
        }
    }
}