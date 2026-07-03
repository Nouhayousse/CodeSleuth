"""
CodeSleuth - Scanner Agent (ADK)
Agent LLM dont les "yeux" sont les tools exposés par notre serveur MCP GitHub.
Sa seule responsabilité : récupérer les données brutes du repo, pas les analyser.
"""

import os
import sys
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

# Chemin absolu recommandé pour éviter les soucis de répertoire de travail
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
        timeout=15.0,  # scan d'un gros repo peut prendre un peu de temps
    ),
    tool_filter=[
        "scan_github_repository",
    ],
)

scanner_agent = LlmAgent(
    name="scanner_agent",
    model=os.getenv("CODESLEUTH_MODEL", "gemini-3.1-flash-lite"),
    description="Récupère la structure brute d'un repo GitHub : fichiers, dépendances, activité.",
    instruction="""
Tu es le Scanner Agent de CodeSleuth. Ton unique rôle est de collecter des données
brutes sur un repo GitHub — tu ne fais AUCUNE analyse de qualité de code, ça n'est
pas ton travail (c'est celui de l'Analyst Agent qui viendra après toi).

Quand on te donne un owner/repo :
1. Appelle l'outil scan_github_repository pour récupérer toutes les données brutes
   (structure, dépendances, activité de commit) en un seul appel.
2. Résume ces données brutes de façon structurée (pas d'opinion, juste les faits)

Ne tente jamais d'halluciner des données GitHub que tu n'as pas obtenues via les tools.
Si un tool retourne une erreur, signale-le clairement plutôt que d'inventer une réponse.
""",
    tools=[github_toolset],
)