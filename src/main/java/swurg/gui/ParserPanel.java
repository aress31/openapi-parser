package swurg.gui;

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
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.UIManager;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import swurg.gui.tables.models.ParserTableModel;
import swurg.gui.tables.renderers.ParserTableCellRenderer;
import swurg.process.Loader;
import swurg.utilities.RequestWithMetadata;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import swurg.utilities.DataModel;

public class ParserPanel extends JPanel {

  private MontoyaApi montoyaApi;
  private Logging logging;

  private DataModel dataModel;

  private HttpRequestEditor requestViewer;

  private JTextField resourceTextField = new JTextField(64);
  private JTable table;
  private TableRowSorter<TableModel> tableRowSorter;
  private JTextField filterTextField = new JTextField(32);
  private JLabel statusLabel = new JLabel(COPYRIGHT);

  public ParserPanel(MontoyaApi montoyaApi, DataModel dataModel) {
    this.montoyaApi = montoyaApi;
    this.logging = montoyaApi.logging();
    this.dataModel = dataModel;

    initComponents();
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

    return resourcePanel;
  }

  private JButton createBrowseButton() {
    JButton browseButton = new JButton("Browse/Load");
    browseButton.setBackground(UIManager.getColor("Burp.burpOrange"));
    browseButton.setFont(new Font(browseButton.getFont().getName(), Font.BOLD, browseButton.getFont().getSize()));
    browseButton.setForeground(UIManager.getColor("Burp.primaryButtonForeground"));
    browseButton.addActionListener(new browseButtonListener());
    return browseButton;
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
    // Instantiate your custom table dataModel with the column names and data
    ParserTableModel tableModel = new ParserTableModel(dataModel.getRequestDataWithMetadatas());

    // Create the JTable with your custom table dataModel
    JTable table = new JTable(tableModel) {
      @Override
      public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        super.changeSelection(row, col, toggle, extend);

        int modelIndex = tableRowSorter.convertRowIndexToModel(row);
        HttpRequest selectedHttpRequest = ((ParserTableModel) tableModel).getHttpRequestAt(modelIndex);

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

  // Find a way to delete
  public void setModel(DataModel dataModel) {
    this.dataModel = dataModel;
  }

  public void setResourceTextField(String resourceTextField) {
    this.resourceTextField.setText(resourceTextField);
  }

  public void printStatus(String status, Color color) {
    this.statusLabel.setForeground(color);
    this.statusLabel.setText(status);
  }

  class browseButtonListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      if (!(e.getSource() instanceof JButton)) {
        return;
      }

      String resource = getResource((JButton) e.getSource());

      if (resource == null || resource.isEmpty()) {
        printStatus("No file or URL selected.",
            UIManager.getLookAndFeelDefaults().getColor("BurpPalette.red1"));
        return;
      }

      Loader loader = new Loader(montoyaApi);
      try {
        List<RequestWithMetadata> requestWithMetadatas = loader.parseOpenAPI(loader.processOpenAPI(resource));
        updateTableModel(requestWithMetadatas);
        printStatus(COPYRIGHT, UIManager.getLookAndFeelDefaults().getColor("TextField.foreground"));
      } catch (Exception ex) {
        logging.logToOutput(String.format("%s -> %s", this.getClass().getName(), ex.getMessage()));
        printStatus(ex.getMessage(), UIManager.getLookAndFeelDefaults().getColor("BurpPalette.red1"));
      }
    }

    private void updateTableModel(List<RequestWithMetadata> requestWithMetadatas) {
      ParserTableModel tableModel = (ParserTableModel) table.getModel();

      SwingUtilities.invokeLater(() -> {
        for (RequestWithMetadata requestWithMetadata : requestWithMetadatas) {
          tableModel.addRow(requestWithMetadata);
        }
      });
    }

    private String getResource(JButton button) {
      String resource = resourceTextField.getText();

      if (resource.isEmpty()) {
        Preferences prefs = Preferences.userRoot().node(getClass().getName());
        JFileChooser fileChooser = new JFileChooser(prefs.get("LAST_USED_FOLDER", new File(".").getAbsolutePath()));
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("OpenAPI JSON File (*.json)", "json"));
        fileChooser
            .addChoosableFileFilter(new FileNameExtensionFilter("OpenAPI YAML File (*.yml, *.yaml)", "yaml", "yml"));

        if (fileChooser.showOpenDialog(button.getParent()) == JFileChooser.APPROVE_OPTION) {
          File file = fileChooser.getSelectedFile();
          resource = file.getAbsolutePath();
          resourceTextField.setText(resource);
          prefs.put("LAST_USED_FOLDER", file.getParent());
        }
      }

      return resource;
    }
  }
}
