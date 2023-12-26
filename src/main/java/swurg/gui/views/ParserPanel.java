package swurg.gui.views;

import static burp.MyBurpExtension.COPYRIGHT;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.File;
import java.awt.Image;
import java.util.List;
import java.util.prefs.Preferences;

import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelEvent;

import burp.api.montoya.MontoyaApi;
import swurg.gui.components.HistoryFileChooser;
import swurg.gui.components.StatusPanel;
import swurg.gui.components.menus.ParserContextMenu;
import swurg.gui.components.tables.TablePanel;
import swurg.gui.components.tables.models.ParserTableModel;
import swurg.gui.components.tables.renderers.CustomTableCellRenderer;
import swurg.observers.TableModelObserver;
import swurg.workers.Worker;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.http.MyHttpRequest;
import lombok.Getter;

public class ParserPanel extends JPanel implements TableModelObserver {

  private final String TOOLTIP_TEXT = "You need to parse an OpenAPI specification to see its metadata within this tooltip.";

  private final MontoyaApi montoyaApi;
  private final Logging logging;

  @Getter
  private final ParserTableModel parserTableModel;
  @Getter
  private final StatusPanel statusPanel = new StatusPanel();

  private final JLabel metadataLabel = new JLabel();
  @Getter
  private final JTextField resourceTextField = new JTextField();

  private HttpRequestEditor requestViewer;

  private JButton loadButton;
  @Getter
  private JTable table;

  public ParserPanel(MontoyaApi montoyaApi) {
    this.montoyaApi = montoyaApi;
    this.logging = montoyaApi.logging();

    this.parserTableModel = new ParserTableModel();

    initComponents();
    addDocumentListener();

    ToolTipManager.sharedInstance().setInitialDelay(0);
    ToolTipManager.sharedInstance().setDismissDelay(Integer.MAX_VALUE);
  }

  private void addDocumentListener() {
    this.resourceTextField.getDocument().addDocumentListener(new DocumentListener() {
      private void updateLoadButton() {
        Boolean enabled = !resourceTextField.getText().isBlank();
        SwingUtilities.invokeLater(() -> loadButton.setEnabled(enabled));
      }

      @Override
      public void insertUpdate(DocumentEvent e) {
        updateLoadButton();
      }

      @Override
      public void removeUpdate(DocumentEvent e) {
        updateLoadButton();
      }

      @Override
      public void changedUpdate(DocumentEvent e) {
        // TODO Auto-generated method stub
      }
    });
  }

  private void initComponents() {
    setLayout(new BorderLayout());

    this.add(createNorthPanel(), BorderLayout.NORTH);
    this.add(createSplitPane(), BorderLayout.CENTER);
    this.add(this.statusPanel, BorderLayout.SOUTH);
  }

  public JPanel createNorthPanel() {
    JPanel resourcePanel = new JPanel(new GridBagLayout());

    resourcePanel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0,
        UIManager.getLookAndFeelDefaults().getColor("Separator.foreground")));

    this.loadButton = createButton("Load", new LoadButtonListener());
    this.loadButton.setEnabled(false);

    Icon icon = resizeIcon(UIManager.getIcon("OptionPane.informationIcon"), 26);
    this.metadataLabel.setIcon(icon);
    this.metadataLabel.setToolTipText(this.TOOLTIP_TEXT);

    JPanel eastPanel = new JPanel();
    eastPanel.add(this.metadataLabel);
    eastPanel.add(createButton("Browse", new BrowseButtonListener()));
    eastPanel.add(this.loadButton);

    GridBagConstraints gbc = new GridBagConstraints();

    gbc.insets = new Insets(0, 5, 0, 5);
    resourcePanel.add(new JLabel("Parse from local file or URL:"), gbc);

    gbc.fill = GridBagConstraints.HORIZONTAL;
    gbc.gridx = 1;
    gbc.weightx = 1;
    gbc.insets = new Insets(0, 0, 0, 0);
    resourcePanel.add(this.resourceTextField, gbc);

    gbc.gridx = 2;
    gbc.weightx = 0;
    gbc.insets = new Insets(0, 0, 0, 5);
    resourcePanel.add(eastPanel, gbc);

    return resourcePanel;
  }

  private JSplitPane createSplitPane() {
    this.requestViewer = this.montoyaApi.userInterface()
        .createHttpRequestEditor(burp.api.montoya.ui.editor.EditorOptions.READ_ONLY);

    TablePanel tablePanel = new TablePanel(this.parserTableModel, new CustomTableCellRenderer(), this.requestViewer);
    ParserContextMenu contextMenu = new ParserContextMenu(this.montoyaApi, tablePanel.getTable());
    tablePanel.setContextMenu(contextMenu);

    JTabbedPane tabbedPane = new JTabbedPane();
    tabbedPane.addTab("Request", this.requestViewer.uiComponent());

    JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    splitPane.setTopComponent(tablePanel);
    splitPane.setBottomComponent(tabbedPane);
    splitPane.setResizeWeight(0.6);

    return splitPane;
  }

  private JButton createButton(String buttonText, ActionListener listener) {
    JButton button = new JButton(buttonText);
    button.setBackground(UIManager.getColor("Burp.burpOrange"));
    button.setFont(new Font(button.getFont().getName(), Font.BOLD, button.getFont().getSize()));
    button.setForeground(UIManager.getColor("Burp.primaryButtonForeground"));
    button.addActionListener(listener);

    return button;
  }

  private Icon resizeIcon(Icon originalIcon, int iconWidth) {
    BufferedImage bufferedImage = new BufferedImage(
        originalIcon.getIconWidth(),
        originalIcon.getIconHeight(),
        BufferedImage.TYPE_INT_ARGB);

    Graphics2D graphics2D = bufferedImage.createGraphics();
    originalIcon.paintIcon(null, graphics2D, 0, 0);
    graphics2D.dispose();

    Image scaledImage = bufferedImage.getScaledInstance(iconWidth, iconWidth, Image.SCALE_SMOOTH);

    return new ImageIcon(scaledImage);
  }

  @Override
  public void onMyHttpRequestsUpdate(int event, List<MyHttpRequest> myHttpRequests) {
    if (event == TableModelEvent.DELETE) {
      this.requestViewer.setRequest(null);

      if (myHttpRequests.isEmpty())
        this.metadataLabel.setToolTipText(this.TOOLTIP_TEXT);
    }
  }

  class BrowseButtonListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      if (!(e.getSource() instanceof JButton))
        return;

      String resource = browseForFile((JButton) e.getSource());

      if (resource != null && !resource.isEmpty())
        resourceTextField.setText(resource);
    }

    private String browseForFile(JButton button) {
      Preferences prefs = Preferences.userRoot().node(getClass().getName());
      HistoryFileChooser fileChooser = new HistoryFileChooser(
          prefs.get("LAST_USED_FOLDER", new File(".").getAbsolutePath()));

      // Populate the file chooser's history with previously selected files.
      fileChooser.getHistory().forEach(file -> fileChooser.addFileToHistory(file));

      // Determine the top-level window (JFrame or JDialog) containing the given
      // button.
      Component topLevelWindow = SwingUtilities.getWindowAncestor(button);

      if (fileChooser.showOpenDialog(topLevelWindow) == JFileChooser.APPROVE_OPTION) {
        File file = fileChooser.getSelectedFile();
        String resource = file.getAbsolutePath();

        prefs.put("LAST_USED_FOLDER", file.getParent());
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

      Worker worker = new Worker();

      try {
        List<String> metadataList = worker.parseMetadata(worker.processOpenAPI(resource));
        setMetadataLabel(metadataList);

        List<MyHttpRequest> parsedMyHttpRequests = worker.parseOpenAPI(worker.processOpenAPI(resource));
        parserTableModel.addRows(parsedMyHttpRequests);

        statusPanel.updateStatus(COPYRIGHT, UIManager.getLookAndFeelDefaults().getColor("TextField.foreground"));
      } catch (Exception exception) {
        handleException(exception, resource);
      }
    }

    private void setMetadataLabel(List<String> metadataList) {
      String tooltipText = String.join("\n", metadataList);
      metadataLabel.setToolTipText(tooltipText);
    }

    private void handleException(Exception exception, String resource) {
      logging.raiseErrorEvent(exception.getMessage());

      String message = String.format(
          "Unable to read the OpenAPI resource: %s. Check the extension's error log for the stack trace and report the issue.",
          resource);
      statusPanel.updateStatus(message, UIManager.getLookAndFeelDefaults().getColor("BurpPalette.red1"));
    }
  }
}
