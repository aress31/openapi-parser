package swurg.gui;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import javax.swing.JTabbedPane;

import burp.api.montoya.MontoyaApi;
import swurg.utilities.DataModel;

import lombok.Data;

@Data
public class MainTabGroup extends JTabbedPane {

    private final transient MontoyaApi montoyaApi;

    private ParserPanel parserPanel;
    private ParametersPanel parametersPanel;
    private AboutPanel aboutPanel;

    public MainTabGroup(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;

        initComponents();
    }

    private void initComponents() {
        DataModel parserModel = new DataModel();

        parserPanel = new ParserPanel(montoyaApi, parserModel);
        aboutPanel = new AboutPanel();
        parametersPanel = new ParametersPanel(montoyaApi, parserModel);

        addTab("Parser", parserPanel);
        addTab("About", aboutPanel);

        parserModel.addPropertyChangeListener(new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                // Update the parserModel in ParametersPanel
                parametersPanel.updateParserModel(parserModel);

                // Update the Parameters tab visibility
                updateParametersTabVisibility(parserModel);
            }
        });
    }

    private void updateParametersTabVisibility(DataModel parserModel) {
        boolean hasRequestDataWithMetadatas = !parserModel.getRequestDataWithMetadatas().isEmpty();
        int parametersTabIndex = indexOfTab("Parameters");

        if (hasRequestDataWithMetadatas && parametersTabIndex == -1) {
            addTab("Parameters", parametersPanel);
        } else if (!hasRequestDataWithMetadatas && parametersTabIndex != -1) {
            removeTabAt(parametersTabIndex);
        }
    }
}