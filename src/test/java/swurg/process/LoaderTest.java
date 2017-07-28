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

import java.io.File;
import junit.framework.TestCase;
import swurg.model.Path;
import swurg.model.RESTful;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoaderTest extends TestCase {

    private Logger logger = LoggerFactory.getLogger("LoaderTest");

    public void testProcess() throws Exception {
        
        Loader loader = new Loader();

        RESTful result = loader.process(new File("src/test/resources/testApi.json"));        
        
        assertNotNull("Processed object is null", result);
        
        logger.info("<Schemes......>");

        for (String scheme : result.getSchemes()) {
            logger.info(scheme);
        }

        logger.info("<Path Keys......>");

        for (String pathKey : result.getPaths().keySet()) {
            logger.info(pathKey);

            Path path = result.getPaths().get(pathKey);

            logger.info("<Path......>");
            logger.info("http methods = " + path.getHttpMethods());
        }

        logger.info("TODO - Finish these assertions to check the RESTful object is populated correctly");
    }
}

