"""
CodeSleuth - Analyst Agent
Receives the Scanner Agent's summary (in the conversation history),
selects relevant files, and runs full quality + hotspot analysis via MCP.
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

file_reader_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command=sys.executable,
            args=[_MCP_SERVER_PATH],
        ),
        timeout=60.0,
    ),
    tool_filter=["get_file_content", "analyze_repo_files", "analyze_file_with_hotspot"],
)

analyst_agent = LlmAgent(
    name="analyst_agent",
    model=os.getenv("CODESLEUTH_MODEL", "gemini-3.1-flash-lite"),
    description="Analyzes code quality and identifies hotspots: complexity, churn, duplication, docs, TODOs.",
    instruction="""
You are the Analyst Agent of CodeSleuth. The Scanner Agent has run before you and
listed the repository files in the conversation. Your role: select the most
important Python source files and produce a quality + hotspot analysis.

SELECTION STRATEGY
Choose 2-4 Python files maximum from the most central or largest ones.
Avoid empty __init__.py files, configuration scripts, and test files.

ANALYSIS WORKFLOW
For each selected file, call analyze_file_with_hotspot (not analyze_repo_files) to get:
  - Static quality metrics: long functions, cyclomatic complexity, TODOs, documentation ratio.
  - Commit frequency (churn): how many times the file was modified in the last 90 days.
  - Hotspot score: complexity × churn. This is the key metric.

HOTSPOT REASONING — MANDATORY
After receiving the results, reason explicitly about each file's hotspot status:
  - CRITICAL HOTSPOT: "X is not just complex — it is also the most frequently modified file.
    Every change carries a high probability of regression. This is a priority hotspot."
  - MODERATE HOTSPOT: "Y is moderately complex and regularly modified. Worth monitoring closely."
  - STABLE: "Z is complex but rarely changed. This is legacy debt, lower regression risk."

REPORT FORMAT (structured summary for the Reporter Agent)
For each file analyzed, produce:
  - Hotspot Score: N (complexity=C × commits=K over 90 days) — [CRITICAL HOTSPOT / MODERATE HOTSPOT / STABLE]
  - Max Cyclomatic Complexity: N (function name)
  - Long Functions: list or "None"
  - TODOs/FIXMEs: N
  - Documentation Ratio: N%
  - Your hotspot reasoning sentence.

Do NOT provide remediation recommendations here — that is the Reporter Agent's job.
""",
    tools=[
        file_reader_toolset,
    ],
)