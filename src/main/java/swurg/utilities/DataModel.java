package swurg.utilities;

import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.event.SwingPropertyChangeSupport;

// Might just need a List<RequestWithMetadata> instead of this class
// Just need a workaround to update the ParametersPanel when the ParserPanel is updated
public class DataModel {

    private final List<RequestWithMetadata> requestWithMetadatas = new ArrayList<>();
    private final SwingPropertyChangeSupport swingPropertyChangeSupport = new SwingPropertyChangeSupport(this);

    public void addPropertyChangeListener(PropertyChangeListener propertyChangeListener) {
        swingPropertyChangeSupport.addPropertyChangeListener(propertyChangeListener);
    }

    public void removePropertyChangeListener(PropertyChangeListener propertyChangeListener) {
        swingPropertyChangeSupport.removePropertyChangeListener(propertyChangeListener);
    }

    public List<RequestWithMetadata> getRequestDataWithMetadatas() {
        return new ArrayList<>(this.requestWithMetadatas);
    }
}
