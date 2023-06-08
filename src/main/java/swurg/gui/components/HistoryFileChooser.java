package swurg.gui.components;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.prefs.Preferences;

public class HistoryFileChooser extends JFileChooser {

    private static final String FILE_HISTORY_KEY = "fileHistory";
    private static final int MAX_HISTORY_SIZE = 10;
    private Preferences preferences;
    private List<File> fileHistory;

    public HistoryFileChooser(String currentDirectoryPath) {
        super(currentDirectoryPath);
        preferences = Preferences.userRoot().node(getClass().getName());
        fileHistory = new ArrayList<>();
        loadFileHistory();
        setFileFilter(createFileFilter());
        setAccessory(createHistoryAccessory());
    }

    private FileNameExtensionFilter createFileFilter() {
        return new FileNameExtensionFilter("OpenAPI JSON or YAML File (*.json, *.yml, *.yaml)", "json", "yml", "yaml");
    }

    public void addFileToHistory(File file) {
        if (!fileHistory.contains(file)) {
            fileHistory.add(0, file);
            if (fileHistory.size() > MAX_HISTORY_SIZE) {
                fileHistory.remove(fileHistory.size() - 1);
            }
            saveFileHistory();
        }
    }

    public List<File> getHistory() {
        return fileHistory;
    }

    private JComponent createHistoryAccessory() {
        // Create the JList with the file history
        JList<File> fileList = new JList<>(fileHistory.toArray(new File[0]));
        fileList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        fileList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                File selectedFile = fileList.getSelectedValue();
                setSelectedFile(selectedFile);
            }
        });

        // Wrap the JList inside a JScrollPane for better display and scrolling
        JScrollPane scrollPane = new JScrollPane(fileList);
        scrollPane.setPreferredSize(new Dimension(300, 200));

        return scrollPane;
    }

    private void loadFileHistory() {
        String[] fileHistoryPaths = preferences.get(FILE_HISTORY_KEY, "").split("\n");
        for (String filePath : fileHistoryPaths) {
            if (!filePath.isEmpty()) {
                fileHistory.add(new File(filePath));
            }
        }
    }

    private void saveFileHistory() {
        StringBuilder fileHistoryPaths = new StringBuilder();
        for (File file : fileHistory) {
            fileHistoryPaths.append(file.getAbsolutePath()).append("\n");
        }
        preferences.put(FILE_HISTORY_KEY, fileHistoryPaths.toString());
    }
}
