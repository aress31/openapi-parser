package swurg.gui.views;

import static burp.MyBurpExtension.EXTENSION;
import static burp.MyBurpExtension.VERSION;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Font;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.MessageFormat;
import java.util.Map;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

import org.apache.batik.swing.JSVGCanvas;

import swurg.gui.components.StatusPanel;
import swurg.utilities.HtmlResourceLoader;

public class AboutPanel extends JPanel {

    public AboutPanel() {
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        JPanel svgPanel = createSvgCanvas();
        svgPanel.setPreferredSize(new Dimension(192, 192));
        svgPanel.setBorder(new EmptyBorder(16, 16, 0, 16));

        JPanel contentPanel = createContentPanel();
        contentPanel.setBorder(new EmptyBorder(0, 16, 0, 16));

        add(svgPanel, BorderLayout.NORTH);
        add(contentPanel, BorderLayout.CENTER);
        add(new StatusPanel(), BorderLayout.SOUTH);
    }

    private JPanel createSvgCanvas() {
        JPanel svgPanel = new JPanel(new BorderLayout());
        JSVGCanvas svgCanvas = new JSVGCanvas();

        try {
            URI svgFileURI = getClass().getResource("/images/logo.svg").toURI();
            svgCanvas.setURI(svgFileURI.toString());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        svgCanvas.setOpaque(false);
        svgCanvas.setBackground(new Color(0, 0, 0, 0));

        svgPanel.add(svgCanvas, BorderLayout.CENTER);

        return svgPanel;
    }

    private JPanel createContentPanel() {
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));

        JEditorPane editorPane = createTextLabel();
        JScrollPane scrollPane = new JScrollPane(editorPane);

        contentPanel.add(scrollPane);
        contentPanel.add(Box.createVerticalStrut(16));
        contentPanel.add(createButtonPanel());

        return contentPanel;
    }

    private JEditorPane createTextLabel() {
        String htmlContent = HtmlResourceLoader.loadHtmlContent("aboutText.html");
        String formattedHtmlContent = MessageFormat.format(htmlContent, VERSION, EXTENSION);

        JEditorPane editorPane = new JEditorPane();
        editorPane.setContentType("text/html");
        editorPane.setText(formattedHtmlContent);
        editorPane.setEditable(false);

        return editorPane;
    }

    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));

        Map<String, String> buttonMap = Map.of(
                "<html>Get in touch with <b>Aegis Cyber</b></html>", "https://www.aegiscyber.co.uk",
                "<html>Connect with me on <b>LinkedIn</b></html>", "https://www.linkedin.com/in/alexandre-teyar",
                "<html>Follow me on <b>GitHub</b></html>", "https://github.com/aress31",
                "<html>Submit a <b>pull request</b> or report a <b>bug</b></html>", "https://github.com/aress31/swurg");

        for (Map.Entry<String, String> entry : buttonMap.entrySet()) {
            JButton button = new JButton(entry.getKey());
            button.putClientProperty("html.disable", null);
            button.setAlignmentX(CENTER_ALIGNMENT);
            button.addActionListener(e -> {
                try {
                    Desktop.getDesktop().browse(new URI(entry.getValue()));
                } catch (IOException | URISyntaxException ex) {
                    // Do nothing
                }
            });

            if (entry.getKey().equals(buttonMap.keySet().iterator().next())) {
                button.setBackground(UIManager.getColor("Burp.burpOrange"));
                button.setFont(new Font(button.getFont().getName(), Font.BOLD, button.getFont().getSize()));
                button.setForeground(UIManager.getColor("Burp.primaryButtonForeground"));
            }

            buttonPanel.add(button);
            buttonPanel.add(Box.createVerticalStrut(4));
        }

        return buttonPanel;
    }
}
