package swurg.gui.views;

import static burp.MyBurpExtension.COPYRIGHT;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.List;
import java.util.prefs.Preferences;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import burp.api.montoya.MontoyaApi;
import swurg.gui.components.HistoryFileChooser;
import swurg.gui.components.StatusPanel;
import swurg.gui.components.menus.ParserContextMenu;
import swurg.gui.components.tables.TablePanel;
import swurg.gui.components.tables.models.ParserTableModel;
import swurg.gui.components.tables.renderers.CustomTableCellRenderer;
import swurg.utilities.RequestWithMetadata;
import swurg.workers.Worker;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import lombok.Getter;

public class ParserPanel extends JPanel {

  private MontoyaApi montoyaApi;
  private Logging logging;

  private HttpRequestEditor requestViewer;

  private JTextField resourceTextField = new JTextField(64);
  @Getter
  private JTable table;
  @Getter
  private StatusPanel statusPanel = new StatusPanel();
  @Getter
  private ParserTableModel parserTableModel;

  public ParserPanel(MontoyaApi montoyaApi, List<RequestWithMetadata> requestWithMetadatas) {
    this.montoyaApi = montoyaApi;
    this.logging = montoyaApi.logging();

    ParserTableModel parserTableModel = new ParserTableModel(requestWithMetadatas);
    this.parserTableModel = parserTableModel;

    initComponents();
  }

  private void initComponents() {
    setLayout(new BorderLayout());

    add(createNorthPanel(), BorderLayout.NORTH);
    add(createSplitPane(), BorderLayout.CENTER);
    add(statusPanel, BorderLayout.SOUTH);
  }

  public void setResourceTextField(String text) {
    resourceTextField.setText(text);
  }

  public JPanel createNorthPanel() {
    JPanel resourcePanel = new JPanel();
    resourcePanel.setBorder(BorderFactory.createTitledBorder(""));
    resourcePanel.add(new JLabel("Parse from local file or URL:"));
    resourceTextField.setHorizontalAlignment(SwingConstants.CENTER);
    resourcePanel.add(resourceTextField);
    resourcePanel.add(createButton("Browse", new BrowseButtonListener()));
    resourcePanel.add(createButton("Load", new LoadButtonListener()));

    return resourcePanel;
  }

  private JButton createButton(String buttonText, ActionListener listener) {
    JButton button = new JButton(buttonText);
    button.setBackground(UIManager.getColor("Burp.burpOrange"));
    button.setFont(new Font(button.getFont().getName(), Font.BOLD, button.getFont().getSize()));
    button.setForeground(UIManager.getColor("Burp.primaryButtonForeground"));
    button.addActionListener(listener);

    return button;
  }

  private JSplitPane createSplitPane() {
    JTabbedPane tabbedPane = new JTabbedPane();
    requestViewer = montoyaApi.userInterface()
        .createHttpRequestEditor(burp.api.montoya.ui.editor.EditorOptions.READ_ONLY);
    tabbedPane.addTab("Request", requestViewer.uiComponent());

    JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    TablePanel tablePanel = new TablePanel(parserTableModel, new CustomTableCellRenderer(), requestViewer);
    // Set the context menu using the setter method
    ParserContextMenu contextMenu = new ParserContextMenu(montoyaApi, tablePanel.getTable());
    tablePanel.setContextMenu(contextMenu);
    splitPane.setTopComponent(tablePanel);
    splitPane.setBottomComponent(tabbedPane);
    splitPane.setResizeWeight(0.6);

    return splitPane;
  }

  class BrowseButtonListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      if (!(e.getSource() instanceof JButton)) {
        return;
      }

      String resource = browseForFile((JButton) e.getSource());

      if (resource != null && !resource.isEmpty()) {
        resourceTextField.setText(resource);
      }
    }

    private String browseForFile(JButton button) {
      Preferences prefs = Preferences.userRoot().node(getClass().getName());
      HistoryFileChooser fileChooser = new HistoryFileChooser(
          prefs.get("LAST_USED_FOLDER", new File(".").getAbsolutePath()));

      // Add history to the file chooser
      for (File file : fileChooser.getHistory()) {
        fileChooser.addFileToHistory(file);
      }

      if (fileChooser.showOpenDialog(button.getParent()) == JFileChooser.APPROVE_OPTION) {
        File file = fileChooser.getSelectedFile();
        String resource = file.getAbsolutePath();
        prefs.put("LAST_USED_FOLDER", file.getParent());

        // Add the selected file to history
        fileChooser.addFileToHistory(file);

        return resource;
      }

      return null;
    }
  }

  class LoadButtonListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      String resource = resourceTextField.getText();

      if (resource == null || resource.isEmpty()) {
        statusPanel.updateStatus("No file or URL selected.",
            UIManager.getLookAndFeelDefaults().getColor("BurpPalette.red1"));
        return;
      }

      Worker worker = new Worker(montoyaApi);
      try {
        List<RequestWithMetadata> requestWithMetadatas = worker.parseOpenAPI(worker.processOpenAPI(resource));
        updateTableModel(requestWithMetadatas);
        statusPanel.updateStatus(COPYRIGHT, UIManager.getLookAndFeelDefaults().getColor("TextField.foreground"));
      } catch (Exception ex) {
        String errorMessage = String.format("%s -> %s", this.getClass().getName(), ex.getMessage());
        String statusMessage = String.format(
            "%s -> Check the extension's error log for the stack trace -> Unable to read the OpenAPI resource: %s",
            getClass().getName(), resource);
        logging.logToError(errorMessage);
        statusPanel.updateStatus(statusMessage, UIManager.getLookAndFeelDefaults().getColor("BurpPalette.red1"));
      }
    }

    private void updateTableModel(List<RequestWithMetadata> requestWithMetadatas) {
      SwingUtilities.invokeLater(() -> {
        for (RequestWithMetadata requestWithMetadata : requestWithMetadatas) {
          parserTableModel.addRow(requestWithMetadata);
        }
      });
    }
  }
}
