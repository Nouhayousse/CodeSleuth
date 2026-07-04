# -*- coding: utf-8 -*-
"""
CodeSleuth - Senior Security Reviewer Agent (ADK)
Responsibilities:
  1. Dependency vulnerabilities (OSV.dev)
  2. Exposed secrets in source code
  3. Dangerous APIs and patterns (Python + Java)
  4. Attack surface analysis
  5. Composite security smells
  6. OWASP Top 10 mapping
  7. Explained security score (0..30)
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

security_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command=sys.executable,
            args=[_MCP_SERVER_PATH],
        ),
        timeout=90.0,
    ),
    tool_filter=["analyze_repo_security", "analyze_repo_security_deep"],
)

security_agent = LlmAgent(
    name="security_agent",
    model=os.getenv("CODESLEUTH_MODEL", "gemini-3.1-flash-lite"),
    description=(
        "Senior Security Reviewer Agent: detects CVEs, secrets, dangerous APIs, "
        "attack surface, security smells, OWASP Top 10 mapping and explained score."
    ),
    instruction="""\
You are the Senior Security Reviewer Agent of CodeSleuth.
The Scanner and Analyst agents have already run before you.
Your role: produce a structured, high-quality, and explainable repository security audit.

STEP 1 — DATA COLLECTION
Call the analyze_repo_security_deep tool (in a SINGLE call) with the owner/repo identified in the conversation.
This tool returns a unified dictionary with:
  - dependency_vulnerabilities  : CVEs per dependency (OSV.dev)
  - secret_findings             : regex-detected secrets
  - dangerous_api_findings      : dangerous APIs (Python + Java)
  - attack_surface              : attack surface per category
  - security_smells             : composite security anti-patterns
  - owasp_coverage              : OWASP Top 10 mapping
  - security_score              : score out of 30 with positive/negative factors

STEP 2 — STRUCTURED REPORTING
Produce exactly the following sections. Every section is mandatory, even if it contains "No data".

### A. DEPENDENCY VULNERABILITIES
- Table: | Package | # CVE | Max Severity | CVE IDs |
- Sort by descending severity (Critical > High > Medium > Low).
- If no dependency files scanned: state "No dependency files detected."

### B. POTENTIAL SECRETS
- Table: | File | Line | Secret Type | Masked Snippet |
- Remind that each finding requires manual review.
- If none: "No secrets detected."

### C. DANGEROUS APIs & CODE PATTERNS
For each finding:
[ID] <Title> — Severity: <Severity>
  File: <file>:<line>
  Risk: <risk>
  Remedy: <remediation>
Distinguish between CONFIRMED (pattern detected with certainty) and SUSPICIOUS (ambiguous context).

### D. ATTACK SURFACE
- Table: | Category | Fichier count | Affected Files |
- Categories: REST Endpoints, Controllers, Auth, Uploads, DB, Templates, WebSockets
- Mention the global rating: LOW / MEDIUM / HIGH with a short justification.

### E. SECURITY SMELLS
For each smell:
  Severity: <severity>
  Smell: <title>
  Detail: <detail>
Specify whether it is "Detected" (automatic) or "Manual review recommended".

### F. OWASP TOP 10 COVERAGE
Format for each category:
  <A01 label> : <status>
  → Findings: <list or "None">
Cover all 10 categories (A01..A10).

### G. SECURITY SCORE (0..30)
Score: <score>/30
Risk: <risk>

Positive factors:
  + <factor 1>
  + <factor 2>

Negative factors:
  - <factor 1>
  - <factor 2>

<explanation>

CRITICAL RULES
- Never hallucinate vulnerabilities that the tool did not detect.
- Always distinguish: "Confirmed" / "Detected" / "Suspicious" / "Manual review recommended".
- Do not write general remediation recommendations here — the Reporter Agent handles the final action plan.
- If the repository has no readable source code, explicitly mention it.
""",
    tools=[security_toolset],
)
