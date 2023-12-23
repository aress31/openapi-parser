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
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
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

    openAPI.getServers().forEach(server -> {
      String serverUrl = Optional.ofNullable(server.getUrl())
          .filter(url -> url.startsWith("http://") || url.startsWith("https://"))
          .orElse("https://example.com");

      openAPI.getPaths().forEach(
          (path, pathItem) -> getOperationMap(pathItem).forEach((method, operation) -> Optional.ofNullable(operation)
              .ifPresent(op -> {
                try {
                  URI baseUrl = new URIBuilder(serverUrl).setPath(path).build();
                  HttpService httpService = HttpService.httpService(baseUrl.toString());

                  List<HttpHeader> httpHeaders = buildHttp2RequestHeaders(
                      method, baseUrl, op.getRequestBody(), op.getResponses());

                  List<HttpParameter> httpParameters = buildHttpRequestParameters(
                      op.getParameters(), op.getRequestBody(),
                      openAPI.getComponents().getSchemas());

                  HttpRequest httpRequest = HttpRequest.http2Request(
                      httpService, httpHeaders, ByteArray.byteArray(new byte[0]))
                      .withAddedParameters(httpParameters);

                  int contentLength = httpRequest.body().length();
                  if (contentLength > 0) {
                    httpRequest = httpRequest.withAddedHeader(HttpHeader
                        .httpHeader("content-length", String.valueOf(contentLength)));
                  }

                  logEntries.add(new RequestWithMetadata(httpRequest, op.getDescription()));
                } catch (URISyntaxException e) {
                  throw new RuntimeException(e);
                }
              })));
    });

    return logEntries;
  }

  private Map<String, Operation> getOperationMap(PathItem pathItem) {
    Map<String, Operation> operationMap = new HashMap<>();

    if (pathItem != null) {
      operationMap.put("DELETE", pathItem.getDelete());
      operationMap.put("GET", pathItem.getGet());
      operationMap.put("HEAD", pathItem.getHead());
      operationMap.put("PATCH", pathItem.getPatch());
      operationMap.put("POST", pathItem.getPost());
      operationMap.put("PUT", pathItem.getPut());
      operationMap.put("TRACE", pathItem.getTrace());
    }

    return operationMap;
  }

  private List<HttpHeader> buildHttp2RequestHeaders(String method, URI uri, RequestBody requestBody,
      ApiResponses apiResponses) {
    List<HttpHeader> httpHeaders = new ArrayList<>();

    httpHeaders.add(HttpHeader.httpHeader(":scheme", uri.getScheme()));
    httpHeaders.add(HttpHeader.httpHeader(":method", method));
    httpHeaders.add(HttpHeader.httpHeader(":path", uri.getPath()));
    httpHeaders.add(HttpHeader.httpHeader(":authority", uri.getHost()));

    Optional.ofNullable(apiResponses)
        .map(responses -> responses.get("200"))
        .map(ApiResponse::getContent)
        .map(contentMap -> String.join(",", contentMap.keySet()))
        .ifPresent(acceptHeaderValue -> httpHeaders.add(HttpHeader.httpHeader("accept", acceptHeaderValue)));

    Optional.ofNullable(requestBody)
        .map(RequestBody::getContent)
        .flatMap(contentMap -> contentMap.keySet().stream().findFirst())
        .ifPresent(contentType -> httpHeaders.add(HttpHeader.httpHeader("content-type", contentType)));

    return httpHeaders;
  }

  private List<HttpParameter> buildHttpRequestParameters(List<Parameter> parameters, RequestBody requestBody,
      Map<String, Schema> schemas) {
    List<HttpParameter> httpParameters = new ArrayList<>();

    if (parameters != null)
      parameters.forEach(parameter -> {
        String in = parameter.getIn();
        String name = parameter.getName();
        Schema schema = parameter.getSchema();
        String value = Optional.ofNullable(schema)
            .map(Schema::getType)
            .orElse(null);

        if ("header".equals(in))
          httpParameters.add(HttpParameter.cookieParameter(name, value));
        else if ("query".equals(in))
          httpParameters.add(HttpParameter.urlParameter(name, value));
      });

    if (requestBody != null) {
      requestBody.getContent().entrySet().stream()
          .findFirst()
          .map(Map.Entry::getValue)
          .ifPresent(mediaType -> {
            if (mediaType.getSchema().get$ref() != null) {
              String href = mediaType.getSchema().get$ref();
              String formattedHref = href.substring(href.lastIndexOf("/") + 1);

              Schema schema = schemas.get(formattedHref);
              Map<String, Schema> properties = schema.getProperties();

              if (properties != null) {
                properties.forEach((name, propertySchema) -> {
                  Object example = propertySchema.getExample();
                  String type = propertySchema.getType();
                  String value = Optional.ofNullable(example)
                      .map(Object::toString)
                      .orElse(type);

                  httpParameters.add(HttpParameter.bodyParameter(name, value));
                });
              }
            }
          });
    }

    return httpParameters;
  }
}