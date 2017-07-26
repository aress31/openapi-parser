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

package swurg;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;

import java.util.ArrayList;
import java.util.Map;
import java.util.List;

public class Helper {

    public ArrayList<Scheme> buildSchemes(RESTful api) {
        ArrayList<Scheme> schemes = new ArrayList<Scheme>();

        if (api.getSchemes() != null) {
            for (String protocol: api.getSchemes())
                schemes.add(new Scheme(protocol));
        } else
            schemes.add(schemeFromHost(api.getHost()));

        return schemes;
    }

    public Scheme schemeFromHost(String host) {
        String[] hostParts = host.split(":");  

        if (hostParts.length == 2) {
            int port = Integer.parseInt(hostParts[1]);

            return (new Scheme(port));
        } else
            return null;
    }

    public String validateHostSyntax(String host) {
        // Drop the port number if present
        return host.split(":")[0];
    }

	public String parseParams(List<Parameter> params) {
		String result = "";

		if (params != null) {
            if (!(params.isEmpty())) {
    			for (Parameter param : params) {
    				result += param.getName() + ", ";
    			}

    			result = result.substring(0, result.length() - 2);
            }
		}

		return result;
	}

	public String parseInPathParams(String url, List<Parameter> params) {
		if (params != null) {
			for (Parameter param : params) {
				if (param.getIn().equals("path")) {
					url = url.replace(param.getName(), param.getName() + "=" + param.getType());
				}
			}
		}

		return url;
	}

	public String parseInQueryParams(List<Parameter> params) {
		String result = "";

		if (params != null) {
			result = "?";

			for (Parameter param : params) {
				if (param.getIn().equals("query")) {
					result += param.getName() + "={" + param.getType() + "}&";
				}
			}

			result = result.substring(0, result.length() - 1);
		}

		return result;
	}

	public String parseInBodyParams(List<Parameter> params, JsonObject definitions) {
		String result = "";
		
		if (params != null) {
			for (Parameter param : params) {
				if (param.getIn().equals("body")) {
					result += parseSchemaParams(param.getName(), definitions);
				}
			}
		}

		if (!result.equals("")) {
			result = result.substring(0, result.length() - 1);
		}

		return result;
	}

	// Really messy but does the job -- needs improvements!
	public String parseSchemaParams(String param, JsonObject definitions) {
		Gson gson = new Gson();
		String result = "";

		for (Map.Entry<String, JsonElement> entry: definitions.entrySet()) {
			if (entry.getKey().equals(param)) {
				Schema schema = gson.fromJson(entry.getValue(), Schema.class);

				if (schema.getProperties() != null) {
					for (Map.Entry<String, JsonElement> entry1: schema.getProperties().entrySet()) {
						for (Map.Entry<String, JsonElement> entry2: entry1.getValue().getAsJsonObject().entrySet()) {
							if (entry2.getKey().equals("type")) {
								result += entry1.getKey() + "={" + entry2.getValue().getAsString() + "}&";
							} else if (entry2.getKey().equals("$ref")) {
								String[] parts = entry2.getValue().getAsString().split("/");

								result += parseSchemaParams(parts[parts.length - 1], definitions);
							}
						}
					}
				}
			}
		}

		return result;
	}

	public void populateHttpRequests(List<HttpRequest> httpRequests, String httpMethod, String url, String host, int port, Boolean encryption, List<Parameter> params,	
		JsonObject definitions, List<String> consumes, List<String> produces) {
		String request = "";

		if (consumes != null && produces != null) {
			request = httpMethod + " " + parseInPathParams(url, params) + parseInQueryParams(params) + " HTTP/1.1" + "\n"
			+ "Host: " + host + "\n" 
			+ "Accept: " + String.join(",", produces) + "\n"
			+ "Content-Type: " + String.join(",", consumes)
			+ "\n\n"
			+ parseInBodyParams(params, definitions);
		} else if (consumes != null) {
			request = httpMethod + " " + parseInPathParams(url, params) + parseInQueryParams(params) + " HTTP/1.1" + "\n"
			+ "Host: " + host + "\n" 
			+ "Content-Type: " + String.join(",", consumes)
			+ "\n\n"
			+ parseInBodyParams(params, definitions);
		} else if (produces != null) {
            request = httpMethod + " " + parseInPathParams(url, params) + parseInQueryParams(params) + " HTTP/1.1" + "\n"
            + "Host: " + host + "\n" 
            + "Accept: " + String.join(",", produces)
            + "\n\n"
            + parseInBodyParams(params, definitions);
        } else {                
            request = httpMethod + " " + parseInPathParams(url, params) + parseInQueryParams(params) + " HTTP/1.1" + "\n"
            + "Host: " + host
            + "\n\n"
            + parseInBodyParams(params, definitions);
        }

		HttpRequest httpRequest = new HttpRequest(host, port, encryption, request.getBytes());

		httpRequests.add(httpRequest);
	}
}
