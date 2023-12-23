package burp.http;

import burp.api.montoya.http.message.params.HttpParameter;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@AllArgsConstructor
@Builder
@Data
public class MyHttpParameter {
    private HttpParameter httpParameter;
    private String editedValue;
}
