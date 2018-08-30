/*
#    Copyright (C) 2016 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. 
*/

package swurg.process;

import io.swagger.models.HttpMethod;
import io.swagger.models.Operation;
import io.swagger.models.Path;
import io.swagger.models.Swagger;
import io.swagger.models.parameters.Parameter;
import java.awt.Color;
import java.util.Map;
import junit.framework.TestCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoaderTest extends TestCase {

  private Logger logger = LoggerFactory.getLogger("LoaderTest");

  public void testProcess() {
    String resource = "src/test/resources/petstore.json";

    try {
      Swagger swagger = new Loader().process(resource);

      assertNotNull("Processed object (swagger) is null", swagger);

      logger.info("--- Swagger ---");
      logger.info("Info: " + swagger.getInfo());
      logger.info("Host: " + swagger.getHost());
      logger.info("Base path: " + swagger.getBasePath());
      logger.info("Schemes: " + swagger.getSchemes());
      logger.info("Consumes: " + swagger.getConsumes());
      logger.info("Produces: " + swagger.getProduces());
      logger.info("Paths: " + swagger.getPaths());
      logger.info("Parameters: " + swagger.getParameters());

      for (Map.Entry<String, Path> path : swagger.getPaths().entrySet()) {
        logger.info("--- Endpoint ---");
        logger.info("Path: " + path.getKey());

        for (Map.Entry<HttpMethod, Operation> operation : path.getValue().getOperationMap()
            .entrySet()) {
          logger.info("HTTP Method: " + operation.getKey().toString());
          logger.info("Schemes: " + operation.getValue().getSchemes());
          logger.info("Consumes: " + operation.getValue().getConsumes());
          logger.info("Produces: " + operation.getValue().getProduces());
          logger.info("Parameters: " + operation.getValue().getParameters());

          logger.info("--- Parameter ---");
          for (Parameter parameter : operation.getValue().getParameters()) {
            logger.info("Name: " + parameter.getName());
            logger.info("Type: " + parameter.getIn());
            logger.info("Pattern: " + parameter.getPattern());
          }
        }
      }
    } catch (IllegalArgumentException e) {
      logger.error(String.format("%s is not a file or is an invalid URL", resource),
          Color.RED);
    } catch (NullPointerException e) {
      logger.error(String
              .format("The OpenAPI specification in %s is ill formed and cannot be parsed",
                  resource),
          Color.RED);
    }
  }
}
