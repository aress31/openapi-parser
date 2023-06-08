package burp.http;

import burp.api.montoya.http.message.requests.HttpRequest;
import lombok.AllArgsConstructor;
import lombok.Data;

// Refactor the code to use this class instead of RequestWithMetadata
@AllArgsConstructor
@Data
public class MyHttpRequest {
    private HttpRequest httpRequest;
    private String description;
}
