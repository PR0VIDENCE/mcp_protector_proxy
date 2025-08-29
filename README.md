# MCP Security Proxy

Security middleware for Model Context Protocol servers with tool management, input sanitization, and rate limiting. Includes sample client and server for testing.

## Features

- Tool blocking/allowing with web UI
- ML-based prompt injection detection  
- Configurable rate limiting per tool
- Real-time monitoring and statistics
- Plug-and-play with any standard MCP client/server configuration

## Quick Start

```bash
cd proxy_folder
uv install
python mcp_security_proxy/intermediate.py --target-url http://localhost:8123/mcp --proxy-port 8124
```

Access management UI at `http://localhost:8124`

## Architecture

```
MCP Client → Security Proxy (8124) → Target MCP Server (8123)
                    ↓
            Web Management UI
```

## License

MIT