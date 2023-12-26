package swurg.gui;

import java.util.List;

import javax.swing.JTabbedPane;

import burp.api.montoya.MontoyaApi;
import burp.http.MyHttpRequest;
import lombok.Getter;
import swurg.gui.views.AboutPanel;
import swurg.gui.views.ParametersPanel;
import swurg.gui.views.ParserPanel;
import swurg.observers.TableModelObserver;

public class MainTabGroup extends JTabbedPane implements TableModelObserver {

    private final MontoyaApi montoyaApi;

    @Getter
    private ParserPanel parserPanel;
    @Getter
    private ParametersPanel parametersPanel;
    private AboutPanel aboutPanel;

    public MainTabGroup(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;

        initComponents();

        this.parserPanel.getParserTableModel().registerObserver(this);
        this.parserPanel.getParserTableModel().registerObserver(this.parserPanel);
        this.parserPanel.getParserTableModel().registerObserver(this.parametersPanel);
    }

    private void initComponents() {
        parserPanel = new ParserPanel(this.montoyaApi);
        aboutPanel = new AboutPanel(this.montoyaApi);
        parametersPanel = new ParametersPanel(this.montoyaApi);

        this.addTab("Parser", parserPanel);
        this.addTab("About", aboutPanel);
    }

    @Override
    public void onMyHttpRequestsUpdate(int event, List<MyHttpRequest> myHttpRequests) {
        if (indexOfComponent(this.parametersPanel) == -1 && !myHttpRequests.isEmpty()) {
            this.removeTabAt(indexOfComponent(this.aboutPanel));
            this.addTab("Parameters", this.parametersPanel);
            this.addTab("About", this.aboutPanel);
        } else if (indexOfComponent(this.parametersPanel) != -1 && myHttpRequests.isEmpty())
            this.removeTabAt(indexOfComponent(this.parametersPanel));
    }
}