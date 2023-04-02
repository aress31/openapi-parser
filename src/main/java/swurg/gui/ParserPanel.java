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

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.UIManager;

import burp.api.montoya.MontoyaApi;
import swurg.process.Loader;
import swurg.utilities.LogEntry;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.HttpRequestEditor;

public class ParserPanel extends JPanel {

  private MontoyaApi montoyaApi;
  private Logging logging;

  private Model model;
  private HttpRequest currentlyDisplayedItem;

  private HttpRequestEditor requestViewer;

  private JTextField resourceTextField = new JTextField(64);
  private JTable table;
  private TableRowSorter<TableModel> tableRowSorter;
  private JTextField filterTextField = new JTextField(32);
  private JProgressBar progressBar;
  private JLabel statusLabel = new JLabel(COPYRIGHT);

  public ParserPanel(MontoyaApi montoyaApi) {
    this.montoyaApi = montoyaApi;
    this.logging = montoyaApi.logging();

    initComponents();
  }

  private void initComponents() {
    setLayout(new BorderLayout());

    JPanel resourcePanel = initResourcePanel();
    JPanel tablePanel = initTablePanel();

    JTabbedPane tabbedPane = new JTabbedPane();
    requestViewer = montoyaApi.userInterface()
        .createHttpRequestEditor(burp.api.montoya.ui.editor.EditorOptions.READ_ONLY);
    tabbedPane.addTab("Request", requestViewer.uiComponent());

    JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    splitPane.setTopComponent(tablePanel);
    splitPane.setBottomComponent(tabbedPane);

    JPanel southPanel = new JPanel();
    statusLabel.putClientProperty("html.disable", null);
    southPanel.add(statusLabel);

    add(resourcePanel, BorderLayout.NORTH);
    add(splitPane);
    add(southPanel, BorderLayout.SOUTH);
  }

  private JPanel initResourcePanel() {
    resourceTextField.setHorizontalAlignment(SwingConstants.CENTER);

    JButton resourceButton = createResourceButton();

    progressBar = new JProgressBar();
    progressBar.setMinimum(0);
    progressBar.setMaximum(100);
    progressBar.setStringPainted(true);
    progressBar.setVisible(false);

    JPanel resourcePanel = new JPanel();
    resourcePanel.setBorder(BorderFactory.createTitledBorder(""));
    resourcePanel.add(new JLabel("Parse file/URL:"));
    resourcePanel.add(resourceTextField);
    resourcePanel.add(resourceButton);
    resourcePanel.add(progressBar);

    return resourcePanel;
  }

  private JButton createResourceButton() {
    JButton resourceButton = new JButton("Browse/Load");
    resourceButton.setBackground(UIManager.getColor("Burp.burpOrange"));
    resourceButton.setFont(new Font(resourceButton.getFont().getName(), Font.BOLD, resourceButton.getFont().getSize()));
    resourceButton.setForeground(UIManager.getColor("Burp.primaryButtonForeground"));
    resourceButton.addActionListener(new LoadButtonListener());
    return resourceButton;
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

  private void setUpFilterTextField() {
    filterTextField.getDocument().addDocumentListener(new DocumentListener() {
      private void updateFilter() {
        String regex = filterTextField.getText();

        if (regex == null || regex.isEmpty()) {
          tableRowSorter.setRowFilter(null);
        } else {
          tableRowSorter.setRowFilter(RowFilter.regexFilter(regex));
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
    JTable table = new JTable() {
      @Override
      public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        int modelIndex = tableRowSorter.convertRowIndexToModel(row);
        HttpRequest selectedRow = model.getLogEntries().get(modelIndex).getHttpRequest();

        requestViewer.setRequest(selectedRow);
        currentlyDisplayedItem = selectedRow;
        super.changeSelection(row, col, toggle, extend);
      }
    };

    String[] columns = { "#", "Method", "Server", "Path", "Parameters (inHeader, inQuery & inPath)", "Description" };
    Object[][] rows = {};
    table.setModel(new DefaultTableModel(rows, columns) {
      @Override
      public Class<?> getColumnClass(int column) {
        if (column == 0) {
          return Integer.class;
        }
        return super.getColumnClass(column);
      }

      @Override
      public boolean isCellEditable(int row, int column) {
        return false;
      }
    });

    table.setAutoCreateRowSorter(true);
    tableRowSorter = new TableRowSorter<>(table.getModel());
    table.setRowSorter(tableRowSorter);
    return table;
  }

  private void setUpTableMouseListener(ContextMenu contextMenu) {
    table.addMouseListener(new MouseAdapter() {
      @Override
      public void mouseReleased(MouseEvent e) {
        handleContextMenuEvent(e, contextMenu);
      }

      @Override
      public void mousePressed(MouseEvent e) {
        handleContextMenuEvent(e, contextMenu);
      }

      private void handleContextMenuEvent(MouseEvent e, ContextMenu contextMenu) {
        if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
          int selectedRow = table.rowAtPoint(e.getPoint());
          if ((selectedRow >= 0 && selectedRow < table.getRowCount())
              && !table.getSelectionModel().isSelectedIndex(selectedRow)) {
            table.setRowSelectionInterval(selectedRow, selectedRow);
          }
          contextMenu.show(e.getComponent(), e.getX(), e.getY());
          contextMenu.setModel(model);
        }
      }
    });
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

  public JTable getTable() {
    return this.table;
  }

  public void setModel(Model model) {
    this.model = model;
  }

  public void setResourceTextField(String resourceTextField) {
    this.resourceTextField.setText(resourceTextField);
  }

  public void printStatus(String status, Color color) {
    this.statusLabel.setForeground(color);
    this.statusLabel.setText(status);
  }

  class LoadButtonListener implements ActionListener {
    LoadButtonListener() {
    }

    @Override
    public void actionPerformed(ActionEvent e) {
      if (!(e.getSource() instanceof JButton)) {
        return;
      }

      String resource = getResource((JButton) e.getSource());

      if (resource == null || resource.isEmpty()) {
        printStatus("No file or URL selected.",
            javax.swing.UIManager.getLookAndFeelDefaults().getColor("Burp.burpError"));
        return;
      }

      Loader loader = new Loader(montoyaApi);
      try {
        List<LogEntry> logEntries = loader.parseOpenAPI(loader.processOpenAPI(resource));
        model.setLogEntries(logEntries);

        updateTableModel(logEntries);
        printStatus(COPYRIGHT, javax.swing.UIManager.getLookAndFeelDefaults().getColor("TextField.foreground"));
      } catch (Exception ex) {
        logging.logToOutput(String.format("%s -> %s", this.getClass().getName(), ex.getMessage()));
        printStatus(ex.getMessage(), javax.swing.UIManager.getLookAndFeelDefaults().getColor("Burp.burpError"));
      }
    }

    private void updateTableModel(List<LogEntry> logEntries) {
      DefaultTableModel tableModel = (DefaultTableModel) table.getModel();

      for (LogEntry entry : logEntries) {
        tableModel.addRow(new Object[] { tableModel.getRowCount(), entry.getHttpRequest().method(),
            entry.getHttpRequest().httpService().host(), entry.getHttpRequest().path(), entry.getParameters(),
            entry.getDescription() != null ? entry.getDescription() : "N/A" });
      }
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
