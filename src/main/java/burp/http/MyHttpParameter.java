package burp.http;

import burp.api.montoya.http.message.params.HttpParameter;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;

@AllArgsConstructor
@Builder
@Data
@EqualsAndHashCode(exclude = "editedValue")
public class MyHttpParameter {
    private HttpParameter httpParameter;
    private String editedValue;
}
