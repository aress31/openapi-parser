package swurg.utilities;

import burp.api.montoya.http.message.requests.HttpRequest;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RequestWithMetadata {
    private HttpRequest httpRequest;
    private String description;
    private String parameters;
}
