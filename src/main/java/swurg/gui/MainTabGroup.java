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

    @Override
    public void onRequestWithMetadatasUpdate() {
        if (indexOfComponent(parametersPanel) == -1 && !requestWithMetadatas.isEmpty()) {
            removeTabAt(indexOfComponent(aboutPanel));
            addTab("Parameters", parametersPanel);
            addTab("About", aboutPanel);
        } else if (indexOfComponent(parametersPanel) != -1 && requestWithMetadatas.isEmpty())
            removeTabAt(indexOfComponent(parametersPanel));

    }
}