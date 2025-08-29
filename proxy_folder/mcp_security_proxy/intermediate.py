"""MCP Security Proxy Middleware Server"""

import argparse
import asyncio
import json
import logging
import time
from collections import defaultdict
from contextlib import AsyncExitStack
from typing import Any, Dict, List, Optional, Set
from mcp_security_proxy.sanitizer import PromptSanitizer

import traceback

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = FastAPI(redirect_slashes=False)


# Instantiates a small ML model that will sanitize inputs from MCP server. 
sanitizer_instance = PromptSanitizer()

class SecurityConfig:
    """Security configuration for the proxy"""
    
    def __init__(self):
        self.blocked_tools: Set[str] = set()
        self.allowed_tools: Set[str] = set()
        self.rate_limits: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'calls_per_minute': 60,
            'last_reset': time.time(),
            'call_count': 0
        })
        self.input_sanitization_enabled = True
        self.dangerous_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'__import__',
            r'subprocess',
            r'os\.system',
            r'shell=True'
        ]


class MCPProxyMiddleware:
    """MCP Proxy Middleware for security and tool management"""
    
    def __init__(self, target_server_url: str, proxy_port: int = 8124):
        self.target_server_url = target_server_url
        self.proxy_port = proxy_port
        self.security_config = SecurityConfig()
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.available_tools: List[Dict[str, Any]] = []
        self.tool_usage_counts: Dict[str, int] = defaultdict(int)
        self.app = FastAPI(title="MCP Security Proxy", version="1.0.0")
        self.setup_routes()
        
    def setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def root():
            return await self.generate_ui()
        
        @self.app.post("/api/toggle-tool")
        async def toggle_tool(request: Request):
            data = await request.json()
            tool_name = data.get("tool_name")
            enabled = data.get("enabled", True)
            
            if enabled:
                self.security_config.blocked_tools.discard(tool_name)
                self.security_config.allowed_tools.add(tool_name)
            else:
                self.security_config.allowed_tools.discard(tool_name)
                self.security_config.blocked_tools.add(tool_name)
                
            return {"success": True, "tool_name": tool_name, "enabled": enabled}
        
        @self.app.get("/api/tools")
        async def get_tools_status():
            tools_status = []
            for tool in self.available_tools:
                tool_name = tool["name"]
                is_enabled = (tool_name not in self.security_config.blocked_tools and
                             (not self.security_config.allowed_tools or 
                              tool_name in self.security_config.allowed_tools))
                rate_limit_info = self.security_config.rate_limits[tool_name]
                tools_status.append({
                    "name": tool_name,
                    "description": tool.get("description", ""),
                    "enabled": is_enabled,
                    "usage_count": self.tool_usage_counts[tool_name],
                    "rate_limit": rate_limit_info['calls_per_minute'],
                    "current_usage": rate_limit_info['call_count']
                })
            return {"tools": tools_status}
        
        @self.app.post("/api/update-rate-limit")
        async def update_rate_limit(request: Request):
            data = await request.json()
            tool_name = data.get("tool_name")
            new_limit = data.get("rate_limit") or 60
            
            if tool_name and new_limit > 0:
                self.security_config.rate_limits[tool_name]['calls_per_minute'] = new_limit
                return {"success": True, "tool_name": tool_name, "rate_limit": new_limit}
            else:
                return {"success": False, "error": "Invalid tool name or rate limit"}
        
        @self.app.get("/api/stats")
        async def get_stats():
            total_tools = len(self.available_tools)
            enabled_tools = sum(1 for tool in self.available_tools 
                              if self.is_tool_allowed(tool["name"]))
            total_usage = sum(self.tool_usage_counts.values())
            
            return {
                "total_tools": total_tools,
                "enabled_tools": enabled_tools,
                "disabled_tools": total_tools - enabled_tools,
                "total_usage": total_usage,
                "tool_usage": dict(self.tool_usage_counts)
            }
        
        @self.app.post("/api/test-usage")
        async def test_usage(request: Request):
            data = await request.json()
            tool_name = data.get("tool_name")
            
            if tool_name and tool_name in [tool["name"] for tool in self.available_tools]:
                # Increment usage counts for testing
                self.tool_usage_counts[tool_name] += 1
                self.security_config.rate_limits[tool_name]['call_count'] += 1
                return {"success": True, "tool_name": tool_name, "new_usage": self.tool_usage_counts[tool_name]}
            else:
                return {"success": False, "error": "Invalid tool name"}
        
        @self.app.post("/mcp/{path:path}")
        async def proxy_mcp(path: str, request: Request):
            logger.info("=== CATCH ALL HANDLER CALLED ===")
            return await self.parse_and_direct_mcp_request(path, request)

    async def connect_to_target_server(self):
        """Connect to the target MCP server"""
        try:
            self._streams_context = streamablehttp_client(
                url=self.target_server_url,
                headers={}
            )
            read_stream, write_stream, _ = await self._streams_context.__aenter__()
            
            self._session_context = ClientSession(read_stream, write_stream)
            self.session = await self._session_context.__aenter__()
            
            await self.session.initialize()
            
            # Get available tools
            response = await self.session.list_tools()
            self.available_tools = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.inputSchema,
                }
                for tool in response.tools
            ]
            
            logger.info(f"Connected to target server. Found {len(self.available_tools)} tools.")
            
        except Exception as e:
            logger.error(f"Failed to connect to target server: {e}")
            raise

    async def parse_and_direct_mcp_request(self, path: str, request: Request):
        """Figures out which handler needs to be called based on method header"""
        body = await request.json()
        method = body.get("method")

        logger.info(f"======Received from CLIENT: {body}")

        logger.info(f"==========Parsing, method is {method}")
        
        if method == "initialize":
            # Handle initialize
            return await self.handle_mcp_request(None, request)
        elif method == "tools/list":
            # Handle tools/list - return your available tools
            return await self.updated_handle_tools_list(None, request)
        elif method == "tools/call":
            # Handle tool execution
            return await self.handle_tool_call(None, request)
        else:
            # default
            return await self.handle_mcp_request(path, request)

    async def handle_mcp_request(self, path: str, request: Request) -> Response:
        """Handle general MCP requests by forwarding to target server"""
        try:
            # Forward the request to the target server
            body = await request.body()
            headers = dict(request.headers)

            # Fix URL construction to avoid double slashes and redirects
            base_url = self.target_server_url.rstrip('/')  # Remove trailing slash
            if path:
                target_url = f"{base_url}/{path.lstrip('/')}"  # Add path, avoiding double slash
            else:
                target_url = base_url  # Just the base URL for empty path
            
            logger.info(f"Proxying {request.method} {request.url.path} -> {target_url}")
            
            async with httpx.AsyncClient(follow_redirects=False) as client:  # Don't follow redirects
                response = await client.request(
                    method=request.method,
                    url=target_url,
                    content=body,
                    headers=headers
                )
                
                # Remove any redirect headers to prevent client-side loops
                response_headers = dict(response.headers)
                response_headers.pop('location', None)
                response_headers.pop('Location', None)

                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=response_headers
                )
                
        except Exception as e:
            logger.error(f"Error forwarding request to {path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
        
    async def updated_handle_tools_list(self, path: str, request: Request) -> Response:
        try:
            # Forward the request to the target server
            body = await request.body()
            headers = dict(request.headers)
            
            # Fix URL construction to avoid double slashes and redirects
            base_url = self.target_server_url.rstrip('/')  # Remove trailing slash
            if path:
                target_url = f"{base_url}/{path.lstrip('/')}"  # Add path, avoiding double slash
            else:
                target_url = base_url  # Just the base URL for empty path
            
            logger.info(f"Proxying {request.method} {request.url.path} -> {target_url}")
            
            async with httpx.AsyncClient(follow_redirects=False) as client:  # Don't follow redirects
                response = await client.request(
                    method=request.method,
                    url=target_url,
                    content=body,
                    headers=headers
                )

                # Extract json data from response
                response_string = response.content.decode()

                lines = response_string.strip().split('\n')
                json_line = next(line for line in lines if line.startswith('data: '))
                json_string = json_line[6:]

                data = json.loads(json_string)

                data['result']['tools'] = [tool for tool in data['result']['tools'] if tool['name'] not in self.security_config.blocked_tools]

                parsed_result = data.get("result").get("tools")

                constructed_string = f"event: message\ndata: {json.dumps(data)}\r\n\r\n"
                encoded_constructed_string = constructed_string.encode()

                # Remove any redirect headers to prevent client-side loops
                response_headers = dict(response.headers)
                response_headers.pop('location', None)
                response_headers.pop('Location', None)

                return Response(
                    content=encoded_constructed_string,
                    status_code=response.status_code,
                    headers=response_headers
                )
                
        except Exception as e:
            logger.error(f"Error forwarding request to {path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def handle_tool_call(self, path: str, request: Request) -> Response:
        """Handle tool call with security checks"""
        try:
            data = await request.json()
            logger.info(f"=====Tool Call Data: {data}")

            tool_name = data.get("params").get("name")
            logger.info(f"=========Tool Name: {tool_name}")
            tool_args = data.get("params").get("arguments", {})
            
            if not self.session:
                raise HTTPException(status_code=503, detail="Not connected to target server")
            
            # Security checks
            if not self.is_tool_allowed(tool_name):
                logger.info(f'allowed tools: {self.security_config.allowed_tools}')
                logger.info(f'allowed tools: {self.security_config.blocked_tools}')
                logger.warning(f"Blocked tool call: {tool_name}")
                raise HTTPException(status_code=403, detail=f"Tool '{tool_name}' is not allowed")
            
            if not self.check_rate_limit(tool_name):
                logger.warning(f"Rate limit exceeded for tool: {tool_name}")
                raise HTTPException(status_code=429, detail=f"Rate limit exceeded for tool '{tool_name}'")
            
            if self.security_config.input_sanitization_enabled:
                sanitized_args = self.sanitize_input(tool_args)
                if sanitized_args != tool_args:
                    logger.warning(f"Input sanitized for tool {tool_name}")
                    tool_args = sanitized_args

            
            # Forward the request to the target server
            body = await request.body()
            headers = dict(request.headers)
            
            # Fix URL construction to avoid double slashes and redirects
            base_url = self.target_server_url.rstrip('/')  # Remove trailing slash
            if path:
                target_url = f"{base_url}/{path.lstrip('/')}"  # Add path, avoiding double slash
            else:
                target_url = base_url  # Just the base URL for empty path
            
            logger.info(f"Proxying {request.method} {request.url.path} -> {target_url}")
            
            async with httpx.AsyncClient(follow_redirects=False) as client:  # Don't follow redirects
                response = await client.request(
                    method=request.method,
                    url=target_url,
                    content=body,
                    headers=headers
                )

                # Check response for prompt injection before returning
                response_string = response.content.decode()
                sanitization_check = sanitizer_instance.check(response_string)
                if sanitization_check['is_injection']:
                    logger.info(sanitization_check)
                    logger.warning(f"Blocked tool call response due to prompt injection: {tool_name}")
                    error_msg = "We found a prompt injection in the response. It has been filtered."

                    
                    new_data = {
                        "content": [
                            {
                                "type": "text",
                                "text": error_msg
                            }
                        ],
                        "structuredContent": {
                            "result": error_msg
                        }
                    }

                    response_headers = dict(response.headers)
                    response_headers.pop('location', None)
                    response_headers.pop('Location', None)

                    response_string: str
                    if response_string.startswith('event: message\r\ndata: '):
                        response_data = json.loads(response_string[22:])
                    else:
                        logger.info("Improper return format. Blocked message.")
                        return Response(
                        content=b'event: message\ndata: ' + json.dumps({
                            
                            "jsonrpc": "2.0",
                            "id": response_data['id'],
                            "result": {
                                "content": [
                                {
                                    "type": "text",
                                    "text": "Message was not in expected format. Blocked."
                                }
                                ],
                                "isError": True
                            }
                            
                        }).encode() + b'\r\n\r\n',
                        status_code=response.status_code,
                        headers=response_headers
                        )
                    return Response(
                        content=b'event: message\ndata: ' + json.dumps({
                            
                            "jsonrpc": "2.0",
                            "id": response_data['id'],
                            "result": {
                                "content": [
                                {
                                    "type": "text",
                                    "text": "Tool response blocked: prompt injection detected."
                                }
                                ],
                                "isError": True
                            }
                            
                        }).encode() + b'\r\n\r\n',
                        status_code=response.status_code,
                        headers=response_headers
                    )
                
                # Remove any redirect headers to prevent client-side loops
                response_headers = dict(response.headers)
                response_headers.pop('location', None)
                response_headers.pop('Location', None)
                
                # Track usage after successful call
                self.tool_usage_counts[tool_name] += 1

                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=response_headers
                )
            
        except HTTPException as httperr:
            logger.error(f"Error: {httperr}")
            raise httperr
        except Exception as e:
            tb_str = traceback.format_exc()
            logger.error(f"Error handling tool call: {e}, \n{tb_str}")
            raise HTTPException(status_code=500, detail=str(e))

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed based on security config"""
        if tool_name in self.security_config.blocked_tools:
            return False
        
        if self.security_config.allowed_tools and tool_name not in self.security_config.allowed_tools:
            return False
            
        return True

    def check_rate_limit(self, tool_name: str) -> bool:
        """Check rate limit for a tool"""
        now = time.time()
        tool_limit = self.security_config.rate_limits[tool_name]
        
        # Reset counter if a minute has passed
        if now - tool_limit['last_reset'] >= 60:
            tool_limit['call_count'] = 0
            tool_limit['last_reset'] = now
        
        # Check if under limit
        if tool_limit['call_count'] >= tool_limit['calls_per_minute']:
            return False
        
        tool_limit['call_count'] += 1
        return True

    def sanitize_input(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize input arguments to prevent dangerous patterns"""
        import re
        
        sanitized = {}
        for key, value in args.items():
            if isinstance(value, str):
                # Check for dangerous patterns
                original_value = value
                for pattern in self.security_config.dangerous_patterns:
                    value = re.sub(pattern, "[BLOCKED]", value, flags=re.IGNORECASE)
                
                if value != original_value:
                    logger.warning(f"Sanitized dangerous pattern in argument '{key}'")
                    
            elif isinstance(value, dict):
                value = self.sanitize_input(value)
            elif isinstance(value, list):
                value = [self.sanitize_input(item) if isinstance(item, dict) else item for item in value]
            
            sanitized[key] = value
        
        return sanitized

    async def generate_ui(self) -> str:
        """Generate enhanced HTML UI for tool management"""
        total_usage = sum(self.tool_usage_counts.values())
        enabled_tools = sum(1 for tool in self.available_tools if self.is_tool_allowed(tool["name"]))
        
        tools_html = ""
        for tool in self.available_tools:
            tool_name = tool["name"]
            description = tool.get("description", "No description available")
            is_enabled = self.is_tool_allowed(tool_name)
            usage_count = self.tool_usage_counts[tool_name]
            rate_limit = self.security_config.rate_limits[tool_name]['calls_per_minute']
            current_usage = self.security_config.rate_limits[tool_name]['call_count']
            
            checked = "checked" if is_enabled else ""
            status_class = "enabled" if is_enabled else "disabled"
            usage_percentage = (current_usage / rate_limit * 100) if rate_limit > 0 else 0
            
            tools_html += f"""
            <div class="tool-card {status_class}">
                <div class="tool-header">
                    <label class="tool-toggle-label">
                        <input type="checkbox" class="tool-toggle" data-tool="{tool_name}" {checked}>
                        <span class="toggle-slider"></span>
                    </label>
                    <div class="tool-info">
                        <h3 class="tool-name">{tool_name}</h3>
                        <div class="tool-stats">
                            <span class="usage-badge">Used: {usage_count}</span>
                            <span class="rate-limit-badge">Limit: {current_usage}/{rate_limit}/min</span>
                        </div>
                    </div>
                </div>
                <div class="tool-description">{description}</div>
                <div class="rate-limit-section">
                    <label class="rate-limit-label">Rate Limit (calls/min):</label>
                    <div class="rate-limit-controls">
                        <input type="number" class="rate-limit-input" data-tool="{tool_name}" 
                               value="{rate_limit}" min="1" max="1000">
                        <button class="update-rate-btn" data-tool="{tool_name}">Update</button>
                    </div>
                    <div class="usage-bar">
                        <div class="usage-fill" style="width: {usage_percentage}%"></div>
                    </div>
                </div>
            </div>
            """
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MCP Security Proxy Dashboard</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                }}
                
                .header {{
                    background: rgba(255, 255, 255, 0.95);
                    backdrop-filter: blur(10px);
                    padding: 30px;
                    border-radius: 20px;
                    margin-bottom: 30px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                    text-align: center;
                }}
                
                .header h1 {{
                    color: #2d3748;
                    font-size: 2.5rem;
                    margin-bottom: 10px;
                    background: linear-gradient(135deg, #667eea, #764ba2);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }}
                
                .header p {{
                    color: #4a5568;
                    font-size: 1.1rem;
                    margin: 5px 0;
                }}
                
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                
                .stat-card {{
                    background: rgba(255, 255, 255, 0.95);
                    backdrop-filter: blur(10px);
                    padding: 25px;
                    border-radius: 15px;
                    text-align: center;
                    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
                    transition: transform 0.3s ease;
                }}
                
                .stat-card:hover {{
                    transform: translateY(-5px);
                }}
                
                .stat-number {{
                    font-size: 2.5rem;
                    font-weight: bold;
                    margin-bottom: 10px;
                }}
                
                .stat-label {{
                    color: #4a5568;
                    font-size: 0.9rem;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }}
                
                .tools-section {{
                    background: rgba(255, 255, 255, 0.95);
                    backdrop-filter: blur(10px);
                    padding: 30px;
                    border-radius: 20px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                }}
                
                .section-title {{
                    color: #2d3748;
                    font-size: 1.8rem;
                    margin-bottom: 25px;
                    text-align: center;
                }}
                
                .tools-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
                    gap: 20px;
                }}
                
                .tool-card {{
                    background: #fff;
                    border-radius: 15px;
                    padding: 20px;
                    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
                    border: 2px solid transparent;
                    transition: all 0.3s ease;
                }}
                
                .tool-card.enabled {{
                    border-color: #48bb78;
                    background: linear-gradient(135deg, #f0fff4, #e6fffa);
                }}
                
                .tool-card.disabled {{
                    border-color: #e53e3e;
                    background: linear-gradient(135deg, #fffaf0, #fed7d7);
                }}
                
                .tool-header {{
                    display: flex;
                    align-items: center;
                    margin-bottom: 15px;
                }}
                
                .tool-toggle-label {{
                    position: relative;
                    display: inline-block;
                    width: 60px;
                    height: 34px;
                    margin-right: 20px;
                }}
                
                .tool-toggle {{
                    opacity: 0;
                    width: 0;
                    height: 0;
                }}
                
                .toggle-slider {{
                    position: absolute;
                    cursor: pointer;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background-color: #ccc;
                    border-radius: 34px;
                    transition: 0.4s;
                }}
                
                .toggle-slider:before {{
                    position: absolute;
                    content: "";
                    height: 26px;
                    width: 26px;
                    left: 4px;
                    bottom: 4px;
                    background-color: white;
                    border-radius: 50%;
                    transition: 0.4s;
                }}
                
                .tool-toggle:checked + .toggle-slider {{
                    background-color: #48bb78;
                }}
                
                .tool-toggle:checked + .toggle-slider:before {{
                    transform: translateX(26px);
                }}
                
                .tool-info {{
                    flex: 1;
                }}
                
                .tool-name {{
                    font-size: 1.2rem;
                    font-weight: 600;
                    color: #2d3748;
                    margin-bottom: 5px;
                }}
                
                .tool-stats {{
                    display: flex;
                    gap: 10px;
                    flex-wrap: wrap;
                }}
                
                .usage-badge, .rate-limit-badge {{
                    font-size: 0.8rem;
                    padding: 4px 8px;
                    border-radius: 12px;
                    font-weight: 500;
                }}
                
                .usage-badge {{
                    background: #e6fffa;
                    color: #234e52;
                    border: 1px solid #81e6d9;
                }}
                
                .rate-limit-badge {{
                    background: #fef5e7;
                    color: #744210;
                    border: 1px solid #f6e05e;
                }}
                
                .tool-description {{
                    color: #4a5568;
                    font-size: 0.9rem;
                    line-height: 1.5;
                    margin-bottom: 15px;
                }}
                
                .rate-limit-section {{
                    background: #f7fafc;
                    padding: 15px;
                    border-radius: 10px;
                    border: 1px solid #e2e8f0;
                }}
                
                .rate-limit-label {{
                    font-weight: 600;
                    color: #2d3748;
                    font-size: 0.9rem;
                    margin-bottom: 8px;
                    display: block;
                }}
                
                .rate-limit-controls {{
                    display: flex;
                    gap: 10px;
                    align-items: center;
                    margin-bottom: 10px;
                }}
                
                .rate-limit-input {{
                    flex: 1;
                    padding: 8px 12px;
                    border: 2px solid #e2e8f0;
                    border-radius: 8px;
                    font-size: 0.9rem;
                    transition: border-color 0.2s;
                }}
                
                .rate-limit-input:focus {{
                    outline: none;
                    border-color: #667eea;
                }}
                
                .update-rate-btn {{
                    padding: 8px 16px;
                    background: linear-gradient(135deg, #667eea, #764ba2);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    font-weight: 600;
                    transition: all 0.2s;
                }}
                
                .update-rate-btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
                }}
                
                .usage-bar {{
                    width: 100%;
                    height: 6px;
                    background: #e2e8f0;
                    border-radius: 3px;
                    overflow: hidden;
                }}
                
                .usage-fill {{
                    height: 100%;
                    background: linear-gradient(90deg, #48bb78, #38a169);
                    transition: width 0.3s ease;
                }}
                
                .status {{
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    padding: 15px 20px;
                    border-radius: 10px;
                    font-weight: 600;
                    z-index: 1000;
                    transition: all 0.3s ease;
                    transform: translateY(-100px);
                    opacity: 0;
                }}
                
                .status.show {{
                    transform: translateY(0);
                    opacity: 1;
                }}
                
                .status.success {{
                    background: #c6f6d5;
                    color: #22543d;
                    border: 2px solid #48bb78;
                }}
                
                .status.error {{
                    background: #fed7d7;
                    color: #742a2a;
                    border: 2px solid #e53e3e;
                }}
                
                @media (max-width: 768px) {{
                    .tools-grid {{
                        grid-template-columns: 1fr;
                    }}
                    
                    .header h1 {{
                        font-size: 2rem;
                    }}
                    
                    .tool-header {{
                        flex-direction: column;
                        align-items: flex-start;
                        gap: 15px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ MCP Security Proxy</h1>
                    <p>Advanced tool management and security controls</p>
                    <p><strong>Target:</strong> <code>{self.target_server_url}</code> • <strong>Port:</strong> {self.proxy_port}</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number" style="color: #667eea;">{len(self.available_tools)}</div>
                        <div class="stat-label">Total Tools</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #48bb78;">{enabled_tools}</div>
                        <div class="stat-label">Enabled Tools</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #e53e3e;">{len(self.available_tools) - enabled_tools}</div>
                        <div class="stat-label">Disabled Tools</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #764ba2;">{total_usage}</div>
                        <div class="stat-label">Total Usage</div>
                    </div>
                </div>
                
                <div class="tools-section">
                    <h2 class="section-title">🔧 Tool Management</h2>
                    <div class="tools-grid">
                        {tools_html}
                    </div>
                </div>
            </div>
            
            <div id="status" class="status"></div>
            
            <script>
                function showStatus(message, type = 'success') {{
                    const status = document.getElementById('status');
                    status.className = `status ${{type}} show`;
                    status.textContent = message;
                    
                    setTimeout(() => {{
                        status.classList.remove('show');
                    }}, 3000);
                }}
                
                // Tool toggle functionality
                document.querySelectorAll('.tool-toggle').forEach(toggle => {{
                    toggle.addEventListener('change', async (e) => {{
                        const toolName = e.target.dataset.tool;
                        const enabled = e.target.checked;
                        
                        try {{
                            const response = await fetch('/api/toggle-tool', {{
                                method: 'POST',
                                headers: {{ 'Content-Type': 'application/json' }},
                                body: JSON.stringify({{ tool_name: toolName, enabled: enabled }})
                            }});
                            
                            if (response.ok) {{
                                const toolCard = e.target.closest('.tool-card');
                                toolCard.className = `tool-card ${{enabled ? 'enabled' : 'disabled'}}`;
                                showStatus(`Tool "${{toolName}}" ${{enabled ? 'enabled' : 'disabled'}}`, 'success');
                                
                                // Refresh stats dynamically
                                setTimeout(refreshData, 500);
                            }} else {{
                                throw new Error('Failed to update tool status');
                            }}
                        }} catch (error) {{
                            showStatus('Error updating tool: ' + error.message, 'error');
                            e.target.checked = !enabled;
                        }}
                    }});
                }});
                
                // Rate limit update functionality
                document.querySelectorAll('.update-rate-btn').forEach(btn => {{
                    btn.addEventListener('click', async (e) => {{
                        const toolName = e.target.dataset.tool;
                        const input = document.querySelector('.rate-limit-input')
                        const newLimit = parseInt(input.value);
                        
                        if (newLimit < 1 || newLimit > 1000) {{
                            showStatus('Rate limit must be between 1 and 1000', 'error');
                            return;
                        }}
                        
                        try {{
                            const response = await fetch('/api/update-rate-limit', {{
                                method: 'POST',
                                headers: {{ 'Content-Type': 'application/json' }},
                                body: JSON.stringify({{ tool_name: toolName, rate_limit: newLimit }})
                            }});
                            
                            if (response.ok) {{
                                showStatus(`Rate limit updated for "${{toolName}}": ${{newLimit}} calls/min`, 'success');
                                // Update the UI dynamically instead of reloading
                                const rateLimitBadge = e.target.closest('.tool-card').querySelector('.rate-limit-badge');
                                if (rateLimitBadge) {{
                                    const currentUsage = rateLimitBadge.textContent.match(/Limit: (\d+)\//)[1] || '0';
                                    rateLimitBadge.textContent = `Limit: ${{currentUsage}}/${{newLimit}}/min`;
                                }}
                                setTimeout(refreshData, 500);
                            }} else {{
                                throw new Error('Failed to update rate limit');
                            }}
                        }} catch (error) {{
                            showStatus('Error updating rate limit: ' + error.message, 'error');
                        }}
                    }});
                }});
                
                // Dynamic update functions
                function updateToolData(toolName, data) {{
                    const toolCard = document.querySelector(`[data-tool="${{toolName}}"]`).closest('.tool-card');
                    if (!toolCard) return;
                    
                    // Update usage count
                    const usageBadge = toolCard.querySelector('.usage-badge');
                    if (usageBadge) {{
                        usageBadge.textContent = `Used: ${{data.usage_count}}`;
                    }}
                    
                    // Update rate limit display
                    const rateLimitBadge = toolCard.querySelector('.rate-limit-badge');
                    if (rateLimitBadge) {{
                        rateLimitBadge.textContent = `Limit: ${{data.current_usage}}/${{data.rate_limit}}/min`;
                    }}
                    
                    // Update rate limit input
                    const rateLimitInput = toolCard.querySelector('.rate-limit-input');
                    if (rateLimitInput) {{
                        rateLimitInput.value = data.rate_limit;
                    }}
                    
                    // Update usage bar
                    const usageFill = toolCard.querySelector('.usage-fill');
                    if (usageFill && data.rate_limit > 0) {{
                        const percentage = (data.current_usage / data.rate_limit * 100);
                        usageFill.style.width = `${{Math.min(percentage, 100)}}%`;
                    }}
                }}
                
                function updateStats(stats) {{
                    const statNumbers = document.querySelectorAll('.stat-number');
                    if (statNumbers.length >= 4) {{
                        statNumbers[0].textContent = stats.total_tools;
                        statNumbers[1].textContent = stats.enabled_tools;
                        statNumbers[2].textContent = stats.disabled_tools;
                        statNumbers[3].textContent = stats.total_usage;
                    }}
                }}
                
                function refreshData() {{
                    // Fetch tools data
                    fetch('/api/tools')
                        .then(response => response.json())
                        .then(data => {{
                            data.tools.forEach(tool => {{
                                updateToolData(tool.name, tool);
                            }});
                        }})
                        .catch(error => console.error('Error refreshing tools:', error));
                    
                    // Fetch stats data
                    fetch('/api/stats')
                        .then(response => response.json())
                        .then(data => {{
                            updateStats(data);
                        }})
                        .catch(error => console.error('Error refreshing stats:', error));
                }}
                
                // Auto-refresh every 10 seconds to update usage stats
                setInterval(refreshData, 10000);
            </script>
        </body>
        </html>
        """

    async def cleanup(self):
        """Clean up connections"""
        try:
            if hasattr(self, '_session_context') and self._session_context:
                await self._session_context.__aexit__(None, None, None)
            if hasattr(self, '_streams_context') and self._streams_context:
                await self._streams_context.__aexit__(None, None, None)
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


async def main():
    """Main function to run the proxy server"""
    parser = argparse.ArgumentParser(description="MCP Security Proxy Middleware")
    parser.add_argument(
        "--target-url", 
        type=str, 
        default="http://localhost:8123/mcp",
        help="Target MCP server URL"
    )
    parser.add_argument(
        "--proxy-port", 
        type=int, 
        default=8124, 
        help="Port for the proxy server"
    )
    args = parser.parse_args()
    
    proxy = MCPProxyMiddleware(args.target_url, args.proxy_port)
    
    try:
        # Connect to target server
        await proxy.connect_to_target_server()
        
        # Start the proxy server
        logger.info(f"Starting MCP Security Proxy on port {args.proxy_port}")
        logger.info(f"Proxying to target server: {args.target_url}")
        logger.info(f"Management UI available at: http://localhost:{args.proxy_port}")
        
        config = uvicorn.Config(
            app=proxy.app,
            host="localhost",
            port=args.proxy_port,
            log_level="info",
            reload=True
        )
        server = uvicorn.Server(config)
        await server.serve()
        
    except KeyboardInterrupt:
        logger.info("Shutting down proxy server...")
    except Exception as e:
        logger.error(f"Error running proxy server: {e}")
    finally:
        await proxy.cleanup()


if __name__ == "__main__":
    asyncio.run(main())