package swurg.process;

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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

public class Loader {

  private final Logging logging;

  public Loader(MontoyaApi montoyaApi) {
    this.logging = montoyaApi.logging();
  }

  public OpenAPI processOpenAPI(String resource) {
    SwaggerParseResult result = readOpenAPI(resource);

    if (result.getMessages() != null && !result.getMessages().isEmpty()) {
      logging.logToError(String.format("%s -> %s", getClass().getName(), result.getMessages()));
      throw new IllegalArgumentException(result.getMessages().toString());
    }

    return result.getOpenAPI();
  }

  private SwaggerParseResult readOpenAPI(String resource) {
    SwaggerParseResult result = null;

    try {
      Path filePath = Paths.get(resource);

      if (Files.exists(filePath) && !Files.isDirectory(filePath)) {
        String openAPIAsString = Files.readString(filePath, StandardCharsets.UTF_8);
        result = new OpenAPIParser().readContents(openAPIAsString, null, null);
      } else {
        throw new InvalidPathException(resource, "File does not exist or is not a file.");
      }
    } catch (InvalidPathException e) {
      try {
        result = new OpenAPIParser().readLocation(resource, null, null);
      } catch (Exception urlEx) {
        logging.logToError(String.format("%s -> Failed to read the resource as a URL: %s",
            getClass().getName(), urlEx.getMessage()));
      }
    } catch (IOException e) {
      logging.logToError(String.format("%s -> Failed to read the resource as a file: %s",
          getClass().getName(), e.getMessage()));
    }

    if (result == null) {
      logging.logToError(String.format("%s -> Unable to read OpenAPI resource: %s", getClass().getName(), resource));
      result = new SwaggerParseResult();
    }

    return result;
  }

  public List<RequestWithMetadata> parseOpenAPI(OpenAPI openAPI) {
    List<RequestWithMetadata> logEntries = new ArrayList<>();

    for (Server server : openAPI.getServers()) {
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
            // List<Parameter> parameters = operation.getParameters();

            StringJoiner stringJoiner = new StringJoiner(", ");

            if (operation.getParameters() != null) {
              operation.getParameters().forEach(parameter -> stringJoiner.add(parameter.getName()));
            }

            try {
              URI fullUri = constructFullRequestUri(new URI(server.getUrl()), pathItem.getKey());

              HttpService httpService = HttpService.httpService(fullUri.getHost(), fullUri.getPort(),
                  fullUri.getPort() == 443);
              List<HttpHeader> httpHeaders = constructRequestHeaders(httpService, fullUri, operation.getRequestBody(),
                  operation.getResponses());
              List<HttpParameter> httpParameters = constructRequestParameters(operation.getParameters(),
                  operation.getRequestBody(), openAPI.getComponents().getSchemas());

              // Content-lentgh is missing
              HttpRequest httpRequest = HttpRequest.http2Request(
                  httpService,
                  httpHeaders,
                  ByteArray.byteArray(new byte[0])).withMethod(method).withPath(fullUri.getPath())
                  .withAddedParameters(httpParameters);

              logEntries.add(
                  createLogEntry(httpRequest, stringJoiner.toString(),
                      operation.getDescription()));
            } catch (URISyntaxException e) {
              logging.logToError(String.format("%s -> %s", this.getClass().getName(), e.getMessage()));
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

  private List<HttpParameter> constructRequestParameters(List<Parameter> parameters, RequestBody requestBody,
      Map<String, Schema> schemas) {
    List<HttpParameter> httpParameters = new ArrayList<>();

    if (parameters != null) {
      for (Parameter parameter : parameters) {
        String in = parameter.getIn();

        if ("header".equals(in)) {
          httpParameters.add(HttpParameter.cookieParameter(parameter.getName(), parameter.getSchema().getType()));
        } else if ("query".equals(in)) {
          httpParameters.add(HttpParameter.urlParameter(parameter.getName(), parameter.getSchema().getType()));
        }
      }
    }

    // Add request body parameters
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

  private List<HttpHeader> constructRequestHeaders(HttpService httpService, URI uri, RequestBody requestBody,
      ApiResponses apiResponses) {
    List<HttpHeader> httpHeaders = new ArrayList<>();

    httpHeaders.add(HttpHeader.httpHeader("Host", uri.getHost()));

    // Set Accept header
    String acceptHeaderValue = parseAccept(apiResponses);
    if (!acceptHeaderValue.isEmpty()) {
      httpHeaders.add(HttpHeader.httpHeader("Accept", acceptHeaderValue));
    }

    // Set Content-Type header
    if (requestBody != null && requestBody.getContent() != null) {
      Optional<String> contentType = requestBody.getContent().keySet().stream().findFirst();
      contentType.ifPresent(value -> httpHeaders.add(HttpHeader.httpHeader("Content-Type", value)));
    }

    return httpHeaders;
  }

  private URI constructFullRequestUri(URI baseUri, String path) throws URISyntaxException {
    String basePath = baseUri.getPath().endsWith("/") ? baseUri.getPath() : baseUri.getPath() + "/";
    String formattedPath = path.startsWith("/") ? path.substring(1) : path;

    return new URIBuilder()
        .setScheme(baseUri.getScheme())
        .setHost(baseUri.getHost())
        .setPort(baseUri.getPort() == -1
            ? (baseUri.getScheme().equals("http") ? 80 : 443)
            : baseUri.getPort())
        .setPath(basePath + formattedPath)
        .build();
  }

  private RequestWithMetadata createLogEntry(HttpRequest httpRequest, String parameters,
      String description) {

    return new RequestWithMetadata(httpRequest, parameters, description);
  }
}
