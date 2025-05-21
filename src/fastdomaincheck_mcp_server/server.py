from mcp.server.fastmcp import FastMCP

# Create MCP server instance
mcp = FastMCP("fastdomaincheck-mcp-server")

@mcp.tool()
def check_domains(domains: list[str]) -> dict[str, dict[str, dict[str, bool]]]:
    """
    Check if multiple domain names are registered.

    Usage:
        Input: A list of domain names to check (e.g. ["example.com", "test.com"])
        Output: JSON object containing registration status of each domain:
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
    """
    from .checker import check_domains_availability
    # Adapt the output to match the documented format
    raw_result = check_domains_availability(domains)
    return {
        "results": {
            k: {"registered": v == "registered"}
            for k, v in raw_result.items()
        }
    }

def main():
    mcp.run()

if __name__ == "__main__":
    main()
