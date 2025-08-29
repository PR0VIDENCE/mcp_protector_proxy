# MCP Security Proxy

A plug-and-play security middleware for Model Context Protocol (MCP) servers that provides tool management, input sanitization, and rate limiting through an intuitive web interface.

## Features

🛡️ **Security Controls**
- Tool blocking/allowing with granular control
- Input sanitization using ML-based prompt injection detection
- Rate limiting per tool with configurable thresholds

🎯 **Easy Management**
- Beautiful web UI for real-time tool management
- Live statistics and usage monitoring
- Dynamic configuration without server restarts

🔌 **Universal Compatibility** 
- Works with any MCP server/client combination
- Transparent proxy - no changes needed to existing setups
- RESTful API for programmatic control

## Quick Start

1. **Install dependencies**
   ```bash
   uv install
   ```

2. **Run the proxy**
   ```bash
   uv run python -m mcp_security_proxy.intermediate --target-url http://localhost:8123/mcp --proxy-port 8124
   ```

3. **Access the management UI**
   Open http://localhost:8124 in your browser

4. **Configure your MCP client**
   Point your MCP client to `http://localhost:8124/mcp` instead of your original server

## Configuration

### Command Line Options

- `--target-url`: Target MCP server URL (default: `http://localhost:8123/mcp`)
- `--proxy-port`: Port for the proxy server (default: `8124`)

### Security Features

**Tool Management**
- Enable/disable individual tools through the UI
- Real-time tool usage statistics
- Configurable rate limits per tool

**Input Sanitization** 
- ML-based prompt injection detection using Hugging Face transformers
- Fallback rule-based detection for reliability
- Automatic filtering of malicious responses

**Rate Limiting**
- Configurable calls per minute per tool
- Automatic reset windows
- Visual usage indicators

## Architecture

```
MCP Client → Security Proxy (Port 8124) → Target MCP Server (Port 8123)
                    ↓
            Web Management UI (Port 8124)
```

The proxy intercepts all MCP protocol messages, applies security policies, and forwards safe requests to the target server.

## API Endpoints

- `GET /` - Management UI
- `POST /api/toggle-tool` - Enable/disable tools
- `GET /api/tools` - Get tool status
- `POST /api/update-rate-limit` - Update rate limits
- `GET /api/stats` - Get usage statistics
- `POST /mcp/{path}` - MCP protocol proxy endpoints

## Development

The project uses:
- **FastAPI** for the web framework
- **Transformers** for ML-based sanitization
- **MCP** library for protocol handling
- **PyTorch** for ML model inference

## License

MIT License