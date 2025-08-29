"""MCP Streamable HTTP Client"""

import argparse
import asyncio
from typing import Optional
from contextlib import AsyncExitStack

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
import httpx
import anyio

from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()


class MCPClient:
    """MCP Client for interacting with an MCP Streamable HTTP server"""

    def __init__(self):
        # Initialize session and client objects
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.anthropic = Anthropic()

    async def connect_to_streamable_http_server(
        self, server_url: str, headers: Optional[dict] = None
    ):
        """Connect to an MCP server running with HTTP Streamable transport"""
        try:
            print(f"Connecting to MCP server at {server_url}...")
            
            self._streams_context = streamablehttp_client(  # pylint: disable=W0201
                url=server_url,
                headers=headers or {},
            )
            read_stream, write_stream, _ = await self._streams_context.__aenter__()  # pylint: disable=E1101

            self._session_context = ClientSession(read_stream, write_stream)  # pylint: disable=W0201
            self.session: ClientSession = await self._session_context.__aenter__()  # pylint: disable=C2801

            await self.session.initialize()
            print("✅ Successfully connected to MCP server!")
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                raise ConnectionError(f"❌ Server rejected request (403 Forbidden). This might be due to:\n"
                                    f"   - Security filtering blocking the request\n"
                                    f"   - Authentication required\n"
                                    f"   - Request contains content flagged as malicious\n"
                                    f"   Server URL: {server_url}")
            elif e.response.status_code == 404:
                raise ConnectionError(f"❌ MCP endpoint not found (404). Please check:\n"
                                    f"   - Server is running on the correct port\n"
                                    f"   - URL path is correct (/mcp)\n"
                                    f"   Server URL: {server_url}")
            elif e.response.status_code >= 500:
                raise ConnectionError(f"❌ Server error ({e.response.status_code}). The MCP server encountered an internal error.\n"
                                    f"   Please check the server logs for more details.\n"
                                    f"   Server URL: {server_url}")
            else:
                raise ConnectionError(f"❌ HTTP error {e.response.status_code}: {e.response.reason_phrase}\n"
                                    f"   Server URL: {server_url}")
        
        except httpx.ConnectError:
            raise ConnectionError(f"❌ Cannot connect to MCP server at {server_url}\n"
                                f"   Please check:\n"
                                f"   - Server is running\n"
                                f"   - Port number is correct\n"
                                f"   - No firewall blocking the connection")
        
        except httpx.TimeoutException:
            raise ConnectionError(f"❌ Connection timeout to MCP server at {server_url}\n"
                                f"   The server took too long to respond. Please check:\n"
                                f"   - Server is running and responsive\n"
                                f"   - Network connectivity")
        
        except Exception as e:
            if "cancel scope" in str(e).lower():
                raise ConnectionError(f"❌ Connection was cancelled, likely due to server-side error\n"
                                    f"   This often happens when:\n"
                                    f"   - Server rejects the connection\n"
                                    f"   - Network issues interrupt the connection\n"
                                    f"   - Server is overloaded\n"
                                    f"   Server URL: {server_url}")
            else:
                raise ConnectionError(f"❌ Unexpected error connecting to MCP server: {str(e)}\n"
                                    f"   Server URL: {server_url}")

    async def process_query(self, query: str) -> str:
        """Process a query using Claude and available tools"""
        messages = [{"role": "user", "content": query}]

        try:
            # Get available tools from MCP server
            response = await self.session.list_tools()

            available_tools = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.inputSchema,
                }
                for tool in response.tools
            ]

            # Initial Claude API call
            response = self.anthropic.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=messages,
                tools=available_tools,
            )

            # Process response and handle tool calls
            final_text = []

            for content in response.content:
                if content.type == "text":
                    final_text.append(content.text)
                elif content.type == "tool_use":
                    tool_name = content.name
                    tool_args = content.input

                    try:
                        print("1")
                        # Execute tool call
                        result = await self.session.call_tool(tool_name, tool_args)
                        print("2")
                        final_text.append(f"[Calling tool {tool_name} with args {tool_args}]")
                        print("3")
                        # Continue conversation with tool results
                        if hasattr(content, "text") and content.text:
                            messages.append({"role": "assistant", "content": content.text})
                        print("4")
                        messages.append({"role": "user", "content": result.content})
                        print("5")
                        # Get next response from Claude
                        response = self.anthropic.messages.create(
                            model="claude-sonnet-4-20250514",
                            max_tokens=1000,
                            messages=messages,
                        )
                        print("6")
                        final_text.append(response.content[0].text)
                        
                    except httpx.HTTPStatusError as e:
                        if e.response.status_code == 403:
                            error_msg = f"⚠️ Tool call blocked: '{tool_name}' was rejected by security filtering.\n" \
                                       f"This might be due to the tool's response containing flagged content."
                        elif e.response.status_code == 429:
                            error_msg = f"⚠️ Rate limit exceeded for tool '{tool_name}'. Please wait and try again."
                        else:
                            error_msg = f"⚠️ Tool call failed: '{tool_name}' returned HTTP {e.response.status_code}"
                        
                        final_text.append(error_msg)
                    
                    except asyncio.CancelledError:
                        error_msg = f"⚠️ Tool call cancelled: '{tool_name}' was interrupted. " \
                                   f"This might be due to server-side filtering or timeout."
                        final_text.append(error_msg)
                    
                    except Exception as e:
                        # Log the exception type for debugging
                        error_type = type(e).__name__
                        error_details = str(e)
                        
                        # Check if it's a 403 error in disguise
                        if "403" in error_details or "not allowed" in error_details.lower() or "forbidden" in error_details.lower():
                            error_msg = f"⚠️ Tool call blocked: '{tool_name}' was rejected by security filtering.\n" \
                                       f"Details: {error_details}"
                        elif "429" in error_details or "rate limit" in error_details.lower():
                            error_msg = f"⚠️ Rate limit exceeded for tool '{tool_name}'. Please wait and try again.\n" \
                                       f"Details: {error_details}"
                        else:
                            error_msg = f"⚠️ Tool call error: '{tool_name}' failed with {error_type}: {error_details}"
                        
                        final_text.append(error_msg)

            return "\n".join(final_text) if final_text else "No response generated."
            
        except Exception as e:
            if "list_tools" in str(e):
                return f"❌ Error: Could not retrieve available tools from MCP server.\n" \
                       f"This might be due to connection issues or server problems.\n" \
                       f"Details: {str(e)}"
            elif "anthropic" in str(e).lower():
                return f"❌ Error: Failed to communicate with Claude API.\n" \
                       f"Please check your API key and internet connection.\n" \
                       f"Details: {str(e)}"
            else:
                return f"❌ Unexpected error processing query: {str(e)}"


    async def chat_loop(self):
        """Run an interactive chat loop"""
        print("\nMCP Client Started!")
        print("Type your queries or 'quit' to exit.")

        while True:
            try:
                query = input("\nQuery: ").strip()

                if query.lower() == "quit":
                    break

                if not query:
                    print("Please enter a query or 'quit' to exit.")
                    continue

                print("Processing query...")
                response = await self.process_query(query)
                print(f"\nResponse:\n{response}")

            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except EOFError:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Error in chat loop: {str(e)}")

    async def cleanup(self):
        """Properly clean up the session and streams"""
        try:
            print("Cleaning up connections...")
            if hasattr(self, '_session_context') and self._session_context:
                await self._session_context.__aexit__(None, None, None)
            if hasattr(self, '_streams_context') and self._streams_context:
                await self._streams_context.__aexit__(None, None, None)  # pylint: disable=E1101
            print("✅ Cleanup completed.")
        except Exception as e:
            print(f"⚠️ Warning during cleanup: {str(e)}")
            # Continue with cleanup even if there are errors


async def main():
    """Main function to run the MCP client"""
    parser = argparse.ArgumentParser(description="Run MCP Streamable HTTP based Client")
    parser.add_argument(
        "--mcp-localhost-port", type=int, default=8123, help="Localhost port to connect to"
    )
    args = parser.parse_args()

    client = MCPClient()
    connected = False

    try:
        await client.connect_to_streamable_http_server(
            f"http://localhost:{args.mcp_localhost_port}/mcp"
        )
        connected = True
        await client.chat_loop()
        
    except ConnectionError as e:
        print(f"\n{e}")
        print(f"\n💡 Troubleshooting tips:")
        print(f"   1. Make sure the MCP server is running on port {args.mcp_localhost_port}")
        print(f"   2. Check if there's a security proxy blocking requests")
        print(f"   3. Verify the server supports the /mcp endpoint")
        
    except KeyboardInterrupt:
        print("\n\n👋 Client interrupted by user.")
        
    except Exception as e:
        if not connected:
            print(f"❌ Failed to start client: {str(e)}")
        else:
            print(f"❌ Unexpected error: {str(e)}")
            
    finally:
        if connected:
            await client.cleanup()
        else:
            print("Exiting...")


if __name__ == "__main__":
    asyncio.run(main())