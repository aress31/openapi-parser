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

package swurg.model;

import com.google.gson.annotations.Expose;
import java.util.List;
import java.util.Map;

public class HttpMethod {
	private String summary;
	private String description;
	private String operationId;

	private List<String> consumes;
	private List<String> produces;
	
	private List<Parameter> parameters;
    private Map<Integer, HttpCode> responses;

	public HttpMethod(String summary, String description, List<String> consumes, List<String> produces, List<Parameter> parameters, Map<Integer, HttpCode> responses) {		
		this.summary = summary;
		this.description = description;
		this.consumes = consumes;
		this.produces = produces;
		this.parameters = parameters;
		this.responses = responses;
    }
	
    public List<String> getConsumes() {
    	return this.consumes;
    }
    
    public List<String> getProduces() {
    	return this.produces;
    }
    
    public List<Parameter> getParameters() {
    	return this.parameters;
    }
    
    public Map<Integer, HttpCode> getResponses() {
    	return this.responses;
    }
}
