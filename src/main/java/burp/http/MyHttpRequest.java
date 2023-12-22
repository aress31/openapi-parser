package burp.http;

import burp.api.montoya.http.message.requests.HttpRequest;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class MyHttpRequest {
    private HttpRequest httpRequest;
    // TODO: Monitor the future integration of metadata or notes support to
    // eliminate the necessity of this redundant helper class.
    private String description;
}
