<p align="center">
  <img alt="logo" src="https://raw.githubusercontent.com/AresS31/swurg/dev/images/logo3.png" height="200">
  <p align="center">
      <a href="https://portswigger.net/bappstore/6bf7574b632847faaaa4eb5e42f1757c"><img alt="bapp store" src="https://img.shields.io/badge/BApp-Published-orange.svg"></a>
      <a href="https://www.java.com"><img alt="lang" src="https://img.shields.io/badge/Lang-Java-blue.svg"></a>
      <a href="https://opensource.org/licenses/Apache-2.0"><img alt="license" src="https://img.shields.io/badge/License-Apache%202.0-red.svg"></a>
      <img alt="version" src="https://img.shields.io/badge/Version-2.3-green.svg">
      <img alt="bitcoin" src="https://img.shields.io/badge/Bitcoin-15aFaQaW9cxa4tRocax349JJ7RKyj7YV1p-yellow.svg">
      <img alt="bitcoin cash" src="https://img.shields.io/badge/Bitcoin%20Cash-qqez5ed5wjpwq9znyuhd2hdg86nquqpjcgkm3t8mg3-yellow.svg">
      <img alt="ether" src="https://img.shields.io/badge/Ether-0x70bC178EC44500C17B554E62BC31EA2B6251f64B-yellow.svg">
  </p>
</p>

## Swurg is a Burp Suite extension designed for OpenAPI testing.

> The OpenAPI Specification (OAS) defines a standard, programming language-agnostic interface description for REST APIs, which allows both humans and computers to discover and understand the capabilities of a service without requiring access to source code, additional documentation, or inspection of network traffic. When properly defined via OpenAPI, a consumer can understand and interact with the remote service with a minimal amount of implementation logic. Similar to what interface descriptions have done for lower-level programming, the OpenAPI Specification removes guesswork in calling a service.
>
> Use cases for machine-readable API definition documents include, but are not limited to: interactive documentation; code generation for documentation, clients, and servers; and automation of test cases. OpenAPI documents describe an API's services and are represented in either YAML or JSON formats. These documents may either be produced and served statically or be generated dynamically from an application.
>
> \- [OpenAPI Initiative](https://github.com/OAI/OpenAPI-Specification)

Performing security assessment of OpenAPI-based APIs can be a tedious task due to Burp Suite (industry standard) lacking native OpenAPI parsing capabilities. A solution to this situation, is to use third-party tools (e.g. `SOAP-UI`) or to implement custom scripts (often on a per engagement basis) to handle the parsing of OpenAPI documents and integrate/chain the results to Burp Suite to use its first class scanning capabilities.

Swurg is an OpenAPI parser that aims to streamline this entire process by allowing security professionals to use Burp Suite as a standalone tool for security assessment of OpenAPI-based APIs.

---

## Supported Features

- OpenAPI documents can be parsed either from a supplied file or URL. The extension can fetch OpenAPI documents directly from a URL using the `Send to Swagger Parser` feature under the `Target -> Site map` context menu.
- Parse OpenAPI documents, formerly known as the `Swagger specification`, fully compliant with OpenAPI 2.0/3.0 Specifications (OAS).
- Requests can be directly viewed/edited within the extension prior to sending them to other Burp tools.
- Requests can be sent to the `Comparer, Intruder, Repeater, Scanner, Site map and Scope` Burp tools.
- Requests matching specific criterias (detailed in the 'Parameters' tab) can be intercepted to automatically match and replace the parsed parameters default values defined in the 'Parameters' tab. This feature allows for fine-tuning of the requests prior to sending them to other Burp tools (e.g., scanner). Edited requests can be viewed within the 'Modified Request (OpenAPI Parser)' tab of Burp's message editor.
- Row highlighting allowing pentesters to highlight "interesting" API calls and/or colour code them for reporting purposes.
- Supports both JSON and YAML formats.

---

## Installation

### Compilation

#### Windows & Unix

1. Install and configure Gradle (<https://gradle.org/>) on your system.
2. Download/clone this repository.

```shell
$ git clone https://github.com/aress31/swurg
$ cd .\swurg\
```

3. Create the standalone jar:

```shell
$ gradle fatJar
```

### Loading the extension into the Burp Suite

In Burp Suite, under the `Extender/Options` tab, click on the `Add` button and load the `swurg-all` jar file located in the `.\build\libs` folder.

Alternatively, you can now directly install/load this extension from the `BApp Store`.

_Note: The version distributed on the `BApp Store` might be behind the version available on this repository._

---

## Possible Improvements

- [ ] Beautify the graphical user interface.
- [ ] Deep parsing of OpenAPI schemas to collect all nested parameters along with their example/type.
- [ ] Code simplification/refactoring.
- [x] Enable cells editing to change API calls directly from the GUI.
- [x] Further optimise the source code.
- [ ] Implement support for authenticated testing (via user-supplied API-keys).
- [x] Improve the Param column by adding the type of parameters (e.g. inquery, inbody, etc.).
- [ ] Implement the tables and context menus.
- [x] Increase the extension verbosity (via the bottom panel).

---

## Dependencies

### Third-party libraries

#### Swagger Parser:

The [Swagger Parser](https://mvnrepository.com/artifact/io.swagger.parser.v3/swagger-parser) library is required and automatically imported in this project.

---

## Project information

In July 2016, after posting a request for improvement on the [PortSwigger support forum](https://support.portswigger.net/customer/portal/questions/16358278-swagger-parser-and-wsdler-improvement), I decided to take the initiative and to implement a solution myself.

The extension is still in development, feedback, comments and contributions are therefore much appreciated.

---

## Sponsor ♥

If you use **and like** the `Swurg/OpenAPI Parser` Burp's extension, please consider donating as a lot of **time** and **efforts** went into building and maintaining this project.

To do so, simply click the "Sponsor" button at the top of this page and select your preferred method of payment.

---

## License

Copyright (C) 2016 - 2022 Alexandre Teyar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
