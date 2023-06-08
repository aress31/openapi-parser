package swurg.utilities;

import burp.api.montoya.http.message.requests.HttpRequest;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RequestWithMetadata {
    private HttpRequest httpRequest;
    // TODO: Remove this field as it is not needed
    // parameters are already in the httpRequest
    private String parameters;
    private String description;
}
