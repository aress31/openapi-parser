package swurg.gui.views;

import static burp.MyBurpExtension.COPYRIGHT;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.List;
import java.util.prefs.Preferences;
import java.util.regex.PatternSyntaxException;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.UIManager;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import swurg.gui.ContextMenu;
import swurg.gui.components.HistoryFileChooser;
import swurg.gui.components.tables.models.ParserTableModel;
import swurg.gui.components.tables.renderers.ParserTableCellRenderer;
import swurg.utilities.RequestWithMetadata;
import swurg.workers.Worker;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.HttpRequestEditor;

public class ParserPanel extends JPanel {

  private MontoyaApi montoyaApi;
  private Logging logging;

  private HttpRequestEditor requestViewer;

  private JTextField resourceTextField = new JTextField(64);
  private JTable table;
  private TableRowSorter<TableModel> tableRowSorter;
  private JTextField filterTextField = new JTextField(32);
  private JLabel statusLabel = new JLabel(COPYRIGHT);

  private ParserTableModel parserTableModel;

  public ParserPanel(MontoyaApi montoyaApi, List<RequestWithMetadata> requestWithMetadatas) {
    this.montoyaApi = montoyaApi;
    this.logging = montoyaApi.logging();

    ParserTableModel parserTableModel = new ParserTableModel(requestWithMetadatas);
    this.parserTableModel = parserTableModel;

    initComponents();
  }

  // Add this method to allow the MainTabGroup to register itself as an observer
  public ParserTableModel getParserTableModel() {
    return parserTableModel;
  }

  private void initComponents() {
    setLayout(new BorderLayout());

    add(initResourcePanel(), BorderLayout.NORTH);
    add(initSplitPane(), BorderLayout.CENTER);
    add(initSouthPanel(), BorderLayout.SOUTH);
  }

  private JPanel initResourcePanel() {
    JPanel resourcePanel = new JPanel();
    resourcePanel.setBorder(BorderFactory.createTitledBorder(""));
    resourcePanel.add(new JLabel("Parse from local file or URL:"));
    resourceTextField.setHorizontalAlignment(SwingConstants.CENTER);
    resourcePanel.add(resourceTextField);
    resourcePanel.add(createBrowseButton());
    resourcePanel.add(createLoadButton());

    return resourcePanel;
  }

  private JButton createBrowseButton() {
    JButton browseButton = new JButton("Browse");
    browseButton.setBackground(UIManager.getColor("Burp.burpOrange"));
    browseButton.setFont(new Font(browseButton.getFont().getName(), Font.BOLD, browseButton.getFont().getSize()));
    browseButton.setForeground(UIManager.getColor("Burp.primaryButtonForeground"));
    browseButton.addActionListener(new BrowseButtonListener());
    return browseButton;
  }

  private JButton createLoadButton() {
    JButton loadButton = new JButton("Load");
    loadButton.setBackground(UIManager.getColor("Burp.burpOrange"));
    loadButton.setFont(new Font(loadButton.getFont().getName(), Font.BOLD, loadButton.getFont().getSize()));
    loadButton.setForeground(UIManager.getColor("Burp.primaryButtonForeground"));
    loadButton.addActionListener(new LoadButtonListener());
    return loadButton;
  }

  private JSplitPane initSplitPane() {
    JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    splitPane.setTopComponent(initTablePanel());
    splitPane.setBottomComponent(initTabbedPane());
    splitPane.setResizeWeight(0.6); // set the resize weight to 0.6
    return splitPane;
  }

  private JTabbedPane initTabbedPane() {
    JTabbedPane tabbedPane = new JTabbedPane();
    requestViewer = montoyaApi.userInterface()
        .createHttpRequestEditor(burp.api.montoya.ui.editor.EditorOptions.READ_ONLY);
    tabbedPane.addTab("Request", requestViewer.uiComponent());
    return tabbedPane;
  }

  private JPanel initTablePanel() {
    setUpFilterTextField();

    table = createTable();
    ContextMenu contextMenu = new ContextMenu(montoyaApi, this);
    setUpTableMouseListener(contextMenu);

    JPanel filterPanel = createFilterPanel();
    JPanel tablePanel = createTablePanel(filterPanel);

    return tablePanel;
  }

  private JPanel initSouthPanel() {
    JPanel southPanel = new JPanel();
    statusLabel.putClientProperty("html.disable", null);
    southPanel.add(statusLabel);
    return southPanel;
  }

  private JPanel createFilterPanel() {
    JPanel filterPanel = new JPanel();
    filterPanel.add(new JLabel("Filter (accepts regular expressions):"));
    filterTextField.setMinimumSize(new Dimension(filterTextField.getPreferredSize()));
    filterPanel.add(filterTextField);
    return filterPanel;
  }

  private JPanel createTablePanel(JPanel filterPanel) {
    JPanel tablePanel = new JPanel(new GridBagLayout());
    GridBagConstraints constraints = new GridBagConstraints();
    constraints.anchor = GridBagConstraints.LINE_START;
    constraints.insets = new Insets(4, 0, 4, 0);
    constraints.gridy = 0;
    constraints.weightx = 0;
    constraints.weighty = 0;

    tablePanel.add(filterPanel, constraints);

    constraints.fill = GridBagConstraints.BOTH;
    constraints.insets = new Insets(0, 0, 0, 0);
    constraints.gridy++;
    constraints.weightx = 1.0;
    constraints.weighty = 1.0;

    tablePanel.add(new JScrollPane(table), constraints);

    return tablePanel;
  }

  private void setUpFilterTextField() {
    filterTextField.getDocument().addDocumentListener(new DocumentListener() {
      private void updateFilter() {
        String regex = filterTextField.getText();
        try {
          tableRowSorter.setRowFilter(regex.isEmpty() ? null : RowFilter.regexFilter(regex));
        } catch (PatternSyntaxException e) {
          // Display an error message if the regex pattern is invalid
          printStatus("Invalid filter pattern: " + e.getMessage(),
              UIManager.getLookAndFeelDefaults().getColor("BurpPalette.red1"));
        }
      }

      @Override
      public void insertUpdate(DocumentEvent e) {
        updateFilter();
      }

      @Override
      public void removeUpdate(DocumentEvent e) {
        updateFilter();
      }

      @Override
      public void changedUpdate(DocumentEvent e) {
        // No action needed
      }
    });
  }

  private JTable createTable() {
    // Create the JTable with your custom table dataModel
    JTable table = new JTable(parserTableModel) {
      @Override
      public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        super.changeSelection(row, col, toggle, extend);

        int modelIndex = tableRowSorter.convertRowIndexToModel(row);
        HttpRequest selectedHttpRequest = ((ParserTableModel) parserTableModel).getHttpRequestAt(modelIndex);

        SwingUtilities.invokeLater(() -> {
          requestViewer.setRequest(selectedHttpRequest);
        });
      }
    };

    // Set the renderer for the table cells colouring support
    table.setDefaultRenderer(Object.class, new ParserTableCellRenderer());

    // Set up the table's row sorter
    table.setAutoCreateRowSorter(true);
    tableRowSorter = new TableRowSorter<>(table.getModel());
    table.setRowSorter(tableRowSorter);

    return table;
  }

  private void setUpTableMouseListener(ContextMenu contextMenu) {
    MouseAdapter mouseAdapter = new MouseAdapter() {
      @Override
      public void mouseReleased(MouseEvent e) {
        handleContextMenuEvent(e);
      }

      @Override
      public void mousePressed(MouseEvent e) {
        handleContextMenuEvent(e);
      }

      private void handleContextMenuEvent(MouseEvent e) {
        if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
          int selectedRow = table.rowAtPoint(e.getPoint());

          if (selectedRow >= 0 && selectedRow < table.getRowCount()
              && !table.getSelectionModel().isSelectedIndex(selectedRow)) {
            table.setRowSelectionInterval(selectedRow, selectedRow);
          }

          contextMenu.show(e.getComponent(), e.getX(), e.getY());
        }
      }
    };

    table.addMouseListener(mouseAdapter);
  }

  // Find a way to delete
  public JTable getTable() {
    return this.table;
  }

  public void setResourceTextField(String resourceTextField) {
    this.resourceTextField.setText(resourceTextField);
  }

  public void printStatus(String status, Color color) {
    this.statusLabel.setForeground(color);
    this.statusLabel.setText(status);
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
        printStatus("No file or URL selected.",
            UIManager.getLookAndFeelDefaults().getColor("BurpPalette.red1"));
        return;
      }

      Worker worker = new Worker(montoyaApi);
      try {
        List<RequestWithMetadata> requestWithMetadatas = worker.parseOpenAPI(worker.processOpenAPI(resource));
        updateTableModel(requestWithMetadatas);
        printStatus(COPYRIGHT, UIManager.getLookAndFeelDefaults().getColor("TextField.foreground"));
      } catch (Exception ex) {
        logging.logToOutput(String.format("%s -> %s", this.getClass().getName(), ex.getMessage()));
        printStatus(ex.getMessage(), UIManager.getLookAndFeelDefaults().getColor("BurpPalette.red1"));
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
