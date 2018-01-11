![oai](images/oai.png)
# swurg
[![Language](https://img.shields.io/badge/Lang-Java-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)](https://opensource.org/licenses/Apache-2.0)

## A Burp Suite extension for RESTful API testing.
During penetration testing of RESTful APIs, it can be time consuming to chain the Burp Suite with other tools such as `SOAP-UI`. However, this is often necessary to parse the desriptions provided by APIs for use with the Burp Suite scanning capabilities. 

Therefore, after posting a request for improvement on the PortSwigger support forum, see [Swagger Parser and Wsdler improvement](https://support.portswigger.net/customer/portal/questions/16358278-swagger-parser-and-wsdler-improvement "Swagger Parser and Wsdler improvement"), in July 2015, I decided to take the lead and implement a solution myself.

The following screenshot shows the plugin interface:

![compilation](images/swurg.png)

## Project information
The extension is still in development, feedback and comments are much appreciated.

## Supported Features
* Parse OpenAPI specifications, previously known as Swagger specifications, supporting JSON and YAML formats.
* Responsive GUI.
* Send requests to the following Burp Suite tabs:
    * Intruder.
    * Repeater.
    * Scanner.
    * Site map.

## Installation
### Compilation 
#### Windows & Linux
1. Install gradle (<https://gradle.org/>)
2. Download the repository.
```
$ git clone https://github.com/AresS31/swurg
$ cd .\swurg\
```
3. Create the swurg jarfile:
```
$ gradle fatJar
```

### Burp Suite settings
In the Burp Suite, under the `Extender/Options` tab, click on the `Add` button and load the `swurg-all` jarfile. 

## Possible Improvements
- [ ] Add new features.
- [ ] Source code optimisation.

## Dependencies
### Third-party libraries
#### Swagger Parser:
The *Swagger Parser* library is required and imported in this project. 

<https://mvnrepository.com/artifact/io.swagger/swagger-parser/1.0.33>

## License
Copyright (C) 2016 - 2018 Alexandre Teyar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
