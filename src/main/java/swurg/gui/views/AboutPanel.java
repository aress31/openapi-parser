package swurg.gui.views;

import static burp.MyBurpExtension.EXTENSION;
import static burp.MyBurpExtension.VERSION;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.MessageFormat;
import java.util.Map;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.batik.swing.JSVGCanvas;

import swurg.gui.components.StatusPanel;
import swurg.utilities.HtmlResourceLoader;

public class AboutPanel extends JPanel {

    public AboutPanel() {
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        JPanel centerPanel = createCenterPanel();

        add(centerPanel, BorderLayout.CENTER);
        add(new StatusPanel(), BorderLayout.SOUTH);
    }

    private JPanel createCenterPanel() {
        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));

        JPanel svgCanvas = createSvgCanvas();
        centerPanel.add(svgCanvas);

        JPanel mainPanel = createContentPanel();
        centerPanel.add(mainPanel);

        JPanel centerContainer = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.CENTER;
        centerContainer.add(centerPanel, gbc);

        return centerContainer;
    }

    private JPanel createSvgCanvas() {
        JPanel svgContainer = new JPanel(new BorderLayout());
        JSVGCanvas svgCanvas = new JSVGCanvas();

        svgContainer.setPreferredSize(new Dimension(512, 512)); // Set fixed size

        try {
            URI svgFileURI = getClass().getResource("/images/logo.svg").toURI();
            svgCanvas.setURI(svgFileURI.toString());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        svgCanvas.setOpaque(false);
        svgCanvas.setBackground(new Color(0, 0, 0, 0));

        svgContainer.add(svgCanvas, BorderLayout.CENTER);

        return svgContainer;
    }

    private JPanel createContentPanel() {
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;

        JLabel textLabel = createTextLabel();
        textLabel.setMaximumSize(new Dimension(400, textLabel.getPreferredSize().height));
        mainPanel.add(textLabel, gbc);

        gbc.gridy++;
        JPanel buttonPanel = createButtonPanel();
        mainPanel.add(buttonPanel, gbc);

        return mainPanel;
    }

    private JLabel createTextLabel() {
        String htmlContent = HtmlResourceLoader.loadHtmlContent("howToText.html");

        String formattedHtmlContent = MessageFormat.format(htmlContent, VERSION, EXTENSION);

        JLabel label = new JLabel(formattedHtmlContent);
        label.putClientProperty("html.disable", null);

        return label;
    }

    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 5, 5, 5);

        Map<String, String> buttonMap = Map.of(
                "<html>Get in touch with <b>Aegis Cyber</b></html>", "https://www.aegiscyber.co.uk",
                "<html>Connect with me on <b>LinkedIn</b></html>", "https://www.linkedin.com/in/alexandre-teyar",
                "<html>Follow me on <b>GitHub</b></html>", "https://github.com/aress31",
                "<html>Submit a <b>pull request</b> or report a <b>bug</b></html>", "https://github.com/aress31/swurg");

        for (Map.Entry<String, String> entry : buttonMap.entrySet()) {
            JButton button = new JButton();
            button.putClientProperty("html.disable", null);
            button.setPreferredSize(new Dimension(192, 40));
            button.setText(entry.getKey());
            button.addActionListener(e -> {
                try {
                    Desktop.getDesktop().browse(new URI(entry.getValue()));
                } catch (IOException | URISyntaxException ex) {
                    // Do nothing
                }
            });

            gbc.gridwidth = GridBagConstraints.REMAINDER; // Set gridwidth to REMAINDER
            gbc.insets = new Insets(5, 5, (gbc.gridy == buttonMap.size() - 1 ? 20 : 5), 5); // Add extra space before
                                                                                            // last button
            buttonPanel.add(button, gbc);
            gbc.gridy++; // Increment gridy
        }

        return buttonPanel;
    }
}
