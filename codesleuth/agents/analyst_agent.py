"""
CodeSleuth - Analyst Agent
Reçoit le résumé du Scanner Agent (dans l'historique de conversation),
choisit les fichiers pertinents, et lance leur analyse complète via MCP.
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

# Toolset MCP dédié à l'Analyst
file_reader_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command=sys.executable,
            args=[_MCP_SERVER_PATH],
        ),
        timeout=30.0,
    ),
    tool_filter=["get_file_content", "analyze_repo_files"],
)

analyst_agent = LlmAgent(
    name="analyst_agent",
    model=os.getenv("CODESLEUTH_MODEL", "gemini-3.1-flash-lite"),
    description="Analyse la qualité du code source : complexité, duplication, documentation, TODOs.",
    instruction="""
Tu es l'Analyst Agent de CodeSleuth. Le Scanner Agent t'a précédé et a listé
les fichiers du repo dans la conversation. Ton rôle : choisir les fichiers
Python les plus importants (fichiers source principaux, pas les fichiers de
config/test triviaux).

Priorise l'analyse sur 2-4 fichiers Python maximum parmi les plus volumineux
ou les plus centraux (évite les __init__.py vides, les fichiers de config).

Appelle l'outil analyze_repo_files pour analyser tous ces fichiers en une seule fois.

Termine par un résumé structuré : pour chaque fichier, liste les smells détectés
avec leur sévérité (CRITIQUE/MAJEUR/MINEUR selon la grille : complexité>15 ou
duplication>80% = MAJEUR, reste = MINEUR). Ne fais AUCUNE recommandation de
remédiation ici — ça sera le rôle du Reporter Agent.
""",
    tools=[
        file_reader_toolset,
    ],
)