package swurg.utilities;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.swagger.util.Json;
import io.swagger.v3.oas.models.media.Schema;

import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map;

public class JSONBodyGenerator {


    public byte[] addJsonToMessage(Map<String, Schema> properties, byte[] httpMessage) throws JsonProcessingException {
        StringBuilder result = new StringBuilder();
        String apiString = Json.pretty(properties);
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode results = objectMapper.createObjectNode();
        JsonNode node = Json.mapper().readTree(apiString);
        for (Iterator<String> it = node.fieldNames(); it.hasNext(); ) {
            String fieldName = it.next();
            addNode(results, fieldName, node.get(fieldName));
        }
        result.append(Json.pretty(results));
        String msg = new String(httpMessage);
        StringBuilder bytes = new StringBuilder();
        return bytes.append(msg).append(result).toString().getBytes(StandardCharsets.UTF_8);
    }

    private void addNode(ObjectNode results, String fieldName, JsonNode node) {
        String type = node.get("type").asText();
        switch (type) {
            case "string" : {
                if(node.get("enum")!=null&& node.get("enum") instanceof ArrayNode) {
                    ArrayNode arrayNode = (ArrayNode) node.get("enum");
                    results.put(fieldName,arrayNode.get(0).asText());
                } else {
                    results.put(fieldName, "string");
                }
                break;
            }
            case "boolean" : {
                results.put(fieldName,true);
                break;
            }
            case "number" : {
                results.put(fieldName,123);
                break;
            }
            case "object" : {
                ObjectNode childNode = results.putObject(fieldName);
                for (Iterator<String> it = node.get("properties").fieldNames(); it.hasNext(); ) {
                    String childField = it.next();
                    addNode(childNode,childField,node.get("properties").get(childField));
                }
                break;
            }
            default: {
                results.put(fieldName,"string");
                break;
            }
        }

    }
}
