package burp.http;

import burp.api.montoya.http.message.params.HttpParameter;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class MyHttpParameter {
    private HttpParameter httpParameter;
    private String editedValue;
}
