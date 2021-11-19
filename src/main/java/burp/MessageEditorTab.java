package burp;

import java.awt.Component;

public class MessageEditorTab implements IMessageEditorTab {

    private byte[] content;
    private boolean isEnabled;
    private IBurpExtenderCallbacks callbacks;
    private ITextEditor textEditor;

    public MessageEditorTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.textEditor = callbacks.createTextEditor();
    }

    @Override
    public String getTabCaption() {
        return "Modified Request (OpenAPI Parser)";
    }

    @Override
    public Component getUiComponent() {
        return this.textEditor.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return isRequest && this.isEnabled;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public void setIsEnabled(boolean isEnabled) {
        this.isEnabled = isEnabled;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.textEditor.setText(this.content);
    }

    @Override
    public byte[] getMessage() {
        return this.textEditor.getText();
    }

    @Override
    public boolean isModified() {
        return this.textEditor.isTextModified();
    }

    @Override
    public byte[] getSelectedData() {
        return this.textEditor.getSelectedText();
    }
}
