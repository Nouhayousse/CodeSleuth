"""
CodeSleuth - Scanner Agent (ADK)
LLM Agent whose "eyes" are the tools exposed by our GitHub MCP server.
Its sole responsibility: retrieve the raw repository data, not analyze it.
"""

import os
import sys
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

_MCP_SERVER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "mcp",
    "github_mcp_server.py",
)

github_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command=sys.executable,
            args=[_MCP_SERVER_PATH],
        ),
        timeout=15.0,
    ),
    tool_filter=[
        "scan_github_repository",
    ],
)

scanner_agent = LlmAgent(
    name="scanner_agent",
    model=os.getenv("CODESLEUTH_MODEL", "gemini-3.1-flash-lite"),
    description="Retrieves the raw structure of a GitHub repository: files, dependencies, activity.",
    instruction="""
You are the Scanner Agent of CodeSleuth. Your sole responsibility is to collect raw
data about a GitHub repository. You must NOT perform any code quality or security
analysis here (that is the job of the Analyst and Security agents that follow you).

When given an owner/repo:
1. Call the scan_github_repository tool to retrieve all raw data
   (structure, dependencies, commit activity) in a single call.
2. Summarize these raw data in a structured, fact-only way (no opinions, no ratings).

Never attempt to hallucinate GitHub data that you did not obtain via the tool.
If a tool returns an error, report it clearly instead of inventing a response.
""",
    tools=[github_toolset],
)