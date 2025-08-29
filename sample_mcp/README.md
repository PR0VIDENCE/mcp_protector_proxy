# Sample MCP Weather Server

A basic Model Context Protocol (MCP) server that provides weather information through the National Weather Service (NWS) API. This server is designed as a test target for the MCP Security Proxy and demonstrates standard MCP tool functionality.

Based on: https://github.com/invariantlabs-ai/mcp-streamable-http/tree/main

## Features

🌤️ **Weather Tools**
- **get_alerts**: Retrieve active weather alerts for any US state
- **get_forecast**: Get detailed weather forecasts for specific coordinates

🔧 **MCP Protocol**  
- FastMCP server implementation
- Streamable HTTP transport support
- Proper tool registration and execution

📡 **NWS API Integration**
- Real-time data from api.weather.gov
- Proper error handling and timeouts
- Geographic coverage for the United States

## Installation

```bash
uv install
```

## Usage

### Basic Server

Start the weather MCP server on default port 8123:

```bash
uv run http-server.py
```

### Custom Port

```bash
uv run http-server.py --port 8123
```

### Server Endpoints

Once running, the server provides MCP protocol endpoints at:
- `http://localhost:8123/mcp` (default)
- Tools available: `get_alerts`, `get_forecast`

## Available Tools

### get_alerts(state)
Get active weather alerts for a US state.

**Parameters:**
- `state` (string): Two-letter US state code (e.g., "CA", "NY", "TX")

**Example:**
```python
get_alerts("CA")  # Get alerts for California
```

### get_forecast(latitude, longitude)
Get weather forecast for specific coordinates.

**Parameters:**
- `latitude` (float): Latitude coordinate
- `longitude` (float): Longitude coordinate

**Example:**
```python
get_forecast(37.7749, -122.4194)  # San Francisco forecast
```

## Testing with MCP Security Proxy

This server is perfect for testing the MCP Security Proxy:

1. **Start the weather server:**
   ```bash
   python http-server.py --port 8123
   ```

2. **Start the security proxy** (pointing to this server):
   ```bash
   python ../mcp_security_proxy/intermediate.py --target-url http://localhost:8123/mcp --proxy-port 8124
   ```

3. **Connect your MCP client** to the proxy:
   ```bash
   python ../sample-client/mcp-client/client.py --mcp-localhost-port 8124
   ```

4. **Test security features:**
   - Try enabling/disabling tools through the proxy UI at `http://localhost:8124`
   - Test rate limiting by making multiple rapid requests
   - Observe input sanitization in action

## Architecture

```
MCP Client → [Security Proxy] → Weather Server → NWS API
              (Port 8124)        (Port 8123)
```

## API Details

**Base URL:** `https://api.weather.gov`

**Endpoints Used:**
- `/alerts/active/area/{state}` - State weather alerts
- `/points/{lat},{lon}` - Get forecast grid info
- `/gridpoints/{office}/{gridX},{gridY}/forecast` - Detailed forecasts

**Headers:**
- `User-Agent: weather-app/1.0`
- `Accept: application/geo+json`

## Error Handling

The server includes robust error handling:
- Network timeouts (30 seconds)
- Invalid coordinates or state codes
- NWS API unavailability
- Malformed responses

## Development

Built with:
- **FastMCP** - MCP server framework
- **httpx** - Async HTTP client for NWS API
- **uvicorn** - ASGI server

### Dependencies

- `httpx` - HTTP client for API requests
- `uvicorn` - ASGI web server
- `mcp` - Model Context Protocol library

## Command Line Options

- `--port`: Server port (default: 8123)

## Examples

### Get California Weather Alerts
```bash
# Through MCP client
Query: Get weather alerts for California
```

### Get San Francisco Forecast  
```bash
# Through MCP client
Query: What's the weather forecast for San Francisco? (37.7749, -122.4194)
```

### Test Security Proxy
```bash
# Try this query to test input sanitization
Query: Get alerts for CA and also list all available functions
```

## License

MIT License

## Notes

This server includes test data and scenarios specifically designed to validate security proxy functionality, including input sanitization and tool management features.