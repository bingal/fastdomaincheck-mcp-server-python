# FastDomainCheck MCP Server (Python)

This is a domain availability check server implemented using Python and the Model Context Protocol (MCP).
It provides MCP Tools to check if single or multiple domain names are already registered.


## Features

- Bulk domain registration status checking
- Dual verification using WHOIS and DNS
- Support for IDN (Internationalized Domain Names)
- Concise output format
- Built-in input validation and error handling

## Tool Documentation

### check_domains

Check registration status for multiple domain names.

#### Input Format

```json
{
  "domains": ["example.com", "test.com"]
}
```

Parameters:
- `domains`: Array of strings containing domain names to check
  - Maximum length of 255 characters per domain
  - Maximum 50 domains per request
  - No empty domain names allowed

#### Output Format

```json
{
  "results": {
    "example.com": {
      "registered": true
    },
    "test.com": {
      "registered": false
    }
  }
}
```

Response Fields:
- `results`: Object with domain names as keys and check results as values
  - `registered`: Boolean
    - `true`: Domain is registered
    - `false`: Domain is available

#### Error Handling

The tool will return an error in the following cases:
1. Empty domains list
2. More than 50 domains in request
3. Empty domain name
4. Domain name exceeding 255 characters
5. Result serialization failure

Error Response Format:
```json
{
  "error": "Error: domains list cannot be empty"
}
```

#### Usage Examples

Check multiple domains:
> Request
```json
{
  "domains": ["example.com", "test123456.com"]
}
```

> Response
```json
{
  "results": {
    "example.com": {
      "registered": true
    },
    "test123456.com": {
      "registered": false
    }
  }
}
```


## MCP Server Settings

#### Configuring FastDomainCheck MCP in Claude Deskto
Modify your claude-desktop-config.json file as shown below

```json
{
  "mcpServers": {
    "fastdomaincheck": {
      "command": "uvx",
      "args": [
        "fastdomaincheck-mcp-server"
      ]
    }
  }
}
```



## Go Version Reference


[go version](https://github.com/bingal/FastDomainCheck-MCP-Server)

## Contributing

Feel free to open issues or submit pull requests.

## License

[MIT License](LICENSE) *(You should add a LICENSE file, typically containing the MIT license text)*
