# MCP Test Client

A Python-based test client for Model Context Protocol (MCP) servers that uses Claude AI for interactive tool calling and conversation. This client is designed to test MCP server functionality, particularly useful for testing the MCP Security Proxy.

Based on: https://github.com/invariantlabs-ai/mcp-streamable-http/tree/main

## Features

> **Claude AI Integration**
- Uses Claude Sonnet 4 for intelligent conversation
- Automatic tool discovery and usage
- Context-aware responses with tool results

=' **MCP Protocol Support**
- Full MCP Streamable HTTP transport
- Dynamic tool listing and execution  
- Proper session management and cleanup

� **Interactive Chat**
- Real-time chat loop interface
- Comprehensive error handling and user feedback
- Graceful connection management

=� **Security-Aware**
- Handles security proxy responses (403, 429 errors)
- Detailed error messages for troubleshooting
- Connection retry and cleanup mechanisms

## Prerequisites

- Python 3.8+
- Anthropic API key (set in `.env` file)
- Running MCP server (default: localhost:8123)

## Installation

1. **Install dependencies**
   ```bash
   pip install anthropic mcp httpx anyio python-dotenv
   ```

2. **Set up environment**
   Create a `.env` file in this directory:
   ```
   ANTHROPIC_API_KEY=your_anthropic_api_key_here
   ```

## Usage

### Basic Usage

```bash
uv run python client.py
```

This connects to `http://localhost:8123/mcp` by default.

### Custom Port

```bash
uv run python client.py --mcp-localhost-port 8124
```

### Testing with Security Proxy

When testing with the MCP Security Proxy:

1. Start your MCP server on port 8123
2. Start the security proxy on port 8124 (pointing to port 8123)
3. Run the test client pointing to port 8124:
   ```bash
   python client.py --mcp-localhost-port 8124
   ```

## Interactive Commands

Once connected, you can:
- Ask questions that require tool usage
- Test specific tools available on the MCP server
- Type `quit` to exit gracefully

Example queries:
```
Query: What tools are available?
Query: Can you help me with [specific task]?
Query: Test the [tool_name] function
Query: quit
```

## Error Handling

The client provides detailed error messages for common scenarios:

**Connection Issues:**
- Server not running
- Wrong port or URL
- Network connectivity problems

**Security Filtering:**
- Tool calls blocked by proxy (403 errors)
- Rate limiting exceeded (429 errors)
- Content flagged as malicious

**API Issues:**
- Invalid Anthropic API key
- Claude API rate limits
- Tool execution failures

## Architecture

```
Claude AI �� MCP Test Client �� [Security Proxy] �� MCP Server
```

The client:
1. Receives user queries
2. Discovers available MCP tools
3. Sends queries + tools to Claude
4. Executes tool calls via MCP protocol
5. Returns Claude's response with tool results

## Inspired By

This client is inspired by the [MCP Streamable HTTP example](https://github.com/invariantlabs-ai/mcp-streamable-http/tree/main) and adapted for comprehensive testing of MCP servers and security proxies.

## Command Line Options

- `--mcp-localhost-port`: Port number for MCP server connection (default: 8123)

## Troubleshooting

**Connection refused:**
- Ensure MCP server is running on the specified port
- Check if there's a firewall blocking the connection

**403 Forbidden errors:**  
- Tool calls are being blocked by security filtering
- Check security proxy configuration
- Verify tool permissions

**429 Rate limit errors:**
- Too many requests to specific tools
- Wait before retrying or adjust rate limits

**Tool execution failures:**
- Check MCP server logs for errors
- Verify tool parameters and syntax
- Ensure proper MCP protocol implementation