package swurg.workers;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import io.swagger.parser.OpenAPIParser;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import org.apache.http.client.utils.URIBuilder;
import swurg.utilities.RequestWithMetadata;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

public class Worker {

  private final Logging logging;

  public Worker(MontoyaApi montoyaApi) {
    this.logging = montoyaApi.logging();
  }

  public OpenAPI processOpenAPI(String resource) {
    try {
      return readOpenAPI(resource).getOpenAPI();
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex);
    }
  }

  private SwaggerParseResult readOpenAPI(String resource) {
    try {
      SwaggerParseResult result = new OpenAPIParser().readLocation(resource, null, null);

      if (result.getOpenAPI() == null)
        throw new IllegalArgumentException(result.getMessages().toString());

      return result;
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex);
    }
  }

  public List<RequestWithMetadata> parseOpenAPI(OpenAPI openAPI) {
    List<RequestWithMetadata> logEntries = new ArrayList<>();

    for (Server server : openAPI.getServers()) {
      String serverUrl = server.getUrl();
      if (!serverUrl.startsWith("http://") && !serverUrl.startsWith("https://")) {
        serverUrl = "https://example.com" + serverUrl;
      }
      final String finalServerUrl = serverUrl;

      for (Map.Entry<String, PathItem> pathItem : openAPI.getPaths().entrySet()) {
        Map<String, Operation> operationMap = new HashMap<>();
        operationMap.put("DELETE", pathItem.getValue().getDelete());
        operationMap.put("GET", pathItem.getValue().getGet());
        operationMap.put("HEAD", pathItem.getValue().getHead());
        operationMap.put("PATCH", pathItem.getValue().getPatch());
        operationMap.put("POST", pathItem.getValue().getPost());
        operationMap.put("PUT", pathItem.getValue().getPut());
        operationMap.put("TRACE", pathItem.getValue().getTrace());

        operationMap.forEach((method, operation) -> {
          if (operation != null) {
            List<Parameter> parameters = operation.getParameters();
            RequestBody requestBody = operation.getRequestBody();

            try {
              URI baseUrl = new URIBuilder(finalServerUrl).setPath(pathItem.getKey()).build();

              HttpService httpService = HttpService.httpService(baseUrl.toString());
              List<HttpHeader> httpHeaders = buildHttp2RequestHeaders(method, baseUrl, requestBody,
                  operation.getResponses());
              List<HttpParameter> httpParameters = buildHttpRequestParameters(parameters, requestBody,
                  openAPI.getComponents().getSchemas());

              HttpRequest httpRequest = HttpRequest.http2Request(
                  httpService,
                  httpHeaders,
                  ByteArray.byteArray(new byte[0])).withAddedParameters(httpParameters);

              int contentLength = httpRequest.body().length();

              if (contentLength > 0)
                httpRequest = httpRequest.withAddedHeader(HttpHeader
                    .httpHeader("content-length", String.valueOf(contentLength)));

              logEntries.add(
                  createLogEntry(httpRequest, operation.getDescription()));
            } catch (URISyntaxException e) {
              throw new RuntimeException(e);
            }
          }
        });
      }
    }

    return logEntries;
  }

  private String parseAccept(ApiResponses apiResponses) {
    StringJoiner stringJoiner = new StringJoiner(",");

    if (apiResponses != null && apiResponses.get("200") != null && apiResponses.get("200").getContent() != null) {
      for (Map.Entry<String, MediaType> response : apiResponses.get("200").getContent().entrySet()) {
        stringJoiner.add(response.getKey());
      }
    }

    return stringJoiner.toString();
  }

  private List<HttpParameter> buildHttpRequestParameters(List<Parameter> parameters, RequestBody requestBody,
      Map<String, Schema> schemas) {
    List<HttpParameter> httpParameters = new ArrayList<>();

    if (parameters != null) {
      for (Parameter parameter : parameters) {
        String in = parameter.getIn();

        if ("header".equals(in))
          httpParameters.add(HttpParameter.cookieParameter(parameter.getName(), parameter.getSchema().getType()));
        else if ("query".equals(in))
          httpParameters.add(HttpParameter.urlParameter(parameter.getName(), parameter.getSchema().getType()));
      }
    }

    if (requestBody != null) {
      MediaType mediaType = requestBody.getContent().entrySet().stream().findFirst().get().getValue();

      if (mediaType.getSchema().get$ref() != null) {
        String href = mediaType.getSchema().get$ref();
        String[] deconstructedHref = href.split("/");
        String formattedHref = deconstructedHref[deconstructedHref.length - 1];

        Schema schema = schemas.get(formattedHref);

        Map<String, Schema> properties = schema.getProperties();

        if (properties != null) {
          for (Map.Entry<String, Schema> property : properties.entrySet()) {
            Schema propertySchema = property.getValue();
            Object example = propertySchema.getExample();
            String type = example != null ? example.toString() : propertySchema.getType();

            httpParameters.add(HttpParameter.bodyParameter(property.getKey(), type));
          }
        }
      }
    }

    return httpParameters;
  }

  private List<HttpHeader> buildHttp2RequestHeaders(String method, URI uri, RequestBody requestBody,
      ApiResponses apiResponses) {
    List<HttpHeader> httpHeaders = new ArrayList<>();

    httpHeaders.add(HttpHeader.httpHeader(":scheme", uri.getScheme()));
    httpHeaders.add(HttpHeader.httpHeader(":method", method));
    httpHeaders.add(HttpHeader.httpHeader(":path", uri.getPath()));
    httpHeaders.add(HttpHeader.httpHeader(":authority", uri.getHost()));

    String acceptHeaderValue = parseAccept(apiResponses);
    if (!acceptHeaderValue.isEmpty())
      httpHeaders.add(HttpHeader.httpHeader("accept", acceptHeaderValue));

    if (requestBody != null && requestBody.getContent() != null) {
      Optional<String> contentType = requestBody.getContent().keySet().stream().findFirst();
      contentType.ifPresent(value -> httpHeaders.add(HttpHeader.httpHeader("content-type", value)));
    }

    return httpHeaders;
  }

  private RequestWithMetadata createLogEntry(HttpRequest httpRequest, String description) {
    return new RequestWithMetadata(httpRequest, description);
  }
}
