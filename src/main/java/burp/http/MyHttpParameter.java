package burp.http;

import java.util.Objects;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import lombok.Data;

@Data
public class MyHttpParameter implements HttpParameter {
    private String name;
    private String value;
    private HttpParameterType type;
    private String editedValue;

    public MyHttpParameter(HttpParameter httpParameter, String editedValue) {
        this.name = httpParameter.name();
        this.value = httpParameter.value();
        this.type = httpParameter.type();
        this.editedValue = editedValue;
    }

    public MyHttpParameter(HttpParameter httpParameter) {
        this(httpParameter, null);
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String value() {
        return value;
    }

    @Override
    public HttpParameterType type() {
        return type;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof HttpParameter)) {
            return false;
        }
        HttpParameter other = (HttpParameter) obj;
        return Objects.equals(name, other.name()) && Objects.equals(value, other.value())
                && Objects.equals(type, other.type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(name(), type());
    }
}
