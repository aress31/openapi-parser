# swurg

[![Java CI with Gradle](https://github.com/aress31/swurg/actions/workflows/gradle-build.yml/badge.svg)](https://github.com/aress31/swurg/actions/workflows/gradle-build.yml)
<a href="https://portswigger.net/bappstore/6bf7574b632847faaaa4eb5e42f1757c"><img alt="bapp store" src="https://img.shields.io/badge/BApp-Published-orange.svg"></a>
<a href="https://www.java.com"><img alt="lang" src="https://img.shields.io/badge/Lang-Java-blue.svg"></a>
<a href="https://opensource.org/licenses/Apache-2.0"><img alt="license" src="https://img.shields.io/badge/License-Apache%202.0-red.svg"></a>
<img alt="version" src="https://img.shields.io/badge/Version-2.3-green.svg">

> [!UPDATE]
> This extension has been updated to use the latest [Burp Montoya Java API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/package-summary.html). The extension has undergone a complete overhaul to improve both its UI/UX and performance. These changes ensure that the extension is modern and optimised for use.

## Swurg is a `Burp Suite` extension designed for `OpenAPI`-based `API` testing

> The `OpenAPI` Specification (`OAS`) defines a standard, programming language-agnostic interface description for `REST` `APIs`, which allows both humans and computers to discover and understand the capabilities of a service without requiring access to source code, additional documentation, or inspection of network traffic. When properly defined via `OpenAPI`, a consumer can understand and interact with the remote service with a minimal amount of implementation logic. Similar to what interface descriptions have done for lower-level programming, the `OpenAPI` Specification removes guesswork in calling a service.
>
> Use cases for machine-readable `API` definition documents include, but are not limited to: interactive documentation; code generation for documentation, clients, and servers; and automation of test cases. `OpenAPI` documents describe an `API`'s services and are represented in either `YAML` or `JSON` formats. These documents may either be produced and served statically or be generated dynamically from an application.
>
> \- [`OpenAPI` Initiative](https://github.com/OAI/`OpenAPI`-Specification)

Performing security assessment of `OpenAPI`-based `APIs` can be a tedious task due to `Burp Suite` (industry standard) lacking native `OpenAPI` parsing capabilities. A solution to this situation, is to use third-party tools (e.g. `SOAP-UI`) or to implement custom scripts (often on a per engagement basis) to handle the parsing of `OpenAPI` documents and integrate/chain the results to `Burp Suite` to use its first class scanning capabilities.

Swurg is an `OpenAPI` parser that aims to streamline this entire process by allowing security professionals to use `Burp Suite` as a standalone tool for security assessment of `OpenAPI`-based `APIs`.

## Features

- `OpenAPI` documents can be parsed either from a supplied file or URL. The extension can fetch `OpenAPI` documents directly from a URL using the `Send to Swagger Parser` feature under the `Target -> Site map` context menu.
- Parse `OpenAPI` documents, formerly known as the `Swagger specification`, fully compliant with `OpenAPI` 2.0/3.0 Specifications (`OAS`).
- Requests can be directly viewed/edited within the extension prior to sending them to other Burp tools.
- Requests can be sent to the `Comparer, Intruder, Repeater, Scanner, Site map and Scope` Burp tools.
- Requests matching specific criterias (detailed in the 'Parameters' tab) can be intercepted to automatically match and replace the parsed parameters default values defined in the 'Parameters' tab. This feature allows for fine-tuning of the requests prior to sending them to other Burp tools (e.g., scanner). Edited requests can be viewed within the 'Modified Request (`OpenAPI` Parser)' tab of Burp's message editor.
- Row highlighting allowing pentesters to highlight "interesting" `API` calls and/or colour code them for reporting purposes.
- Includes an export to `CSV` feature, allowing users to easily export selected `API` requests in `CSV` format for further analysis or reporting.
- Supports both `JSON` and `YAML` formats.

## Installation

### 1. Compilation

1. Install and configure [Gradle](https://gradle.org/).

2. Download this repository.

   ```bash
   git clone https://github.com/aress31/swurg
   cd .\swurg\
   ```

3. Create the standalone `jar`:

   ```bash
   gradle clean fatJar
   ```

### 2. Loading the Extension Into the `Burp Suite`

In `Burp Suite`, under the `Extender/Options` tab, click on the `Add` button and load the `swurg-all` jar file located in the `.\build\libs` folder.

Alternatively, you can now directly install/load this extension from the [BApp Store](https://portswigger.net/bappstore/6bf7574b632847faaaa4eb5e42f1757c).

_Note: The version distributed on the [BApp Store](https://portswigger.net/bappstore/6bf7574b632847faaaa4eb5e42f1757c) might be lagging behind the version available on this repository._

## Roadmap

- [ ] Beautify the graphical user interface.
- [ ] Deep parsing of `OpenAPI` schemas to collect all nested parameters along with their example/type.
- [ ] Code simplification/refactoring.
  - [ ] Use `MyHttpRequest` instead of `RequestWithMetadata`.
- [x] Enable cells editing to change `API` calls directly from the `GUI`.
- [ ] Fix the custom request editor tab to work properly with intercepted requests based on the match and replace rulesets.
- [x] Further optimise the source code.
- [ ] Implement support for authenticated testing (via user-supplied `API`-keys).
- [x] Improve the `Param` column by adding parameters type (e.g. `inquery`, `inbody`).
- [ ] Improve the tables and context menus.
- [x] Increase the extension verbosity (via the bottom panel).

## Dependencies

The [Swagger Parser](https://mvnrepository.com/artifact/io.swagger.parser.v3/swagger-parser) library is required and automatically imported in this project.

## Project information

In July 2016, after posting a request for improvement on the [PortSwigger support forum](https://support.portswigger.net/customer/portal/questions/16358278-swagger-parser-and-wsdler-improvement), I decided to take the initiative and to implement a solution myself.

The extension is still in development, feedback, comments and contributions are therefore much appreciated.

## Sponsor 💖

If you want to support this project and appreciate the time invested in developping, maintening and extending it; consider donating toward my next cup of coffee. ☕

It is easy, all you got to do is press the `Sponsor` button at the top of this page or alternatively [click this link](https://github.com/sponsors/aress31). 💸

## Reporting Issues

Found a bug? I would love to squash it! 🐛

Please report all issues on the GitHub [issues tracker](https://github.com/aress31/swurg/issues).

## Contributing

You would like to contribute to better this project? 🤩

Please submit all `PRs` on the GitHub [pull requests tracker](https://github.com/aress31/swurg/pulls).

## License

See [LICENSE](LICENSE).
