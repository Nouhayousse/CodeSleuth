"""
CodeSleuth - Security Agent (ADK)
Responsabilite : analyser les vulnerabilites des dependances (OSV.dev)
et detecter les secrets potentiels dans le code source.
Appelle analyze_repo_security en un seul appel MCP.
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
        timeout=60.0,  # OSV + GitHub peut prendre du temps
    ),
    tool_filter=["analyze_repo_security"],
)

security_agent = LlmAgent(
    name="security_agent",
    model=os.getenv("CODESLEUTH_MODEL", "gemini-3.1-flash-lite"),
    description="Detecte les vulnerabilites de dependances (OSV.dev) et les secrets exposes dans le code.",
    instruction="""
Tu es le Security Agent de CodeSleuth. Le Scanner Agent et l'Analyst Agent ont deja
travaille avant toi. Ton role est d'effectuer l'analyse de securite du repo.

Quand on te donne un owner/repo :
1. Appelle l'outil analyze_repo_security en un seul appel pour obtenir :
   - Les vulnerabilites OSV.dev des dependances Python.
   - Les secrets potentiels detectes par regex dans le code source.

2. Produis un rapport structure avec :
   A. VULNERABILITES DES DEPENDANCES
      - Liste chaque paquet vulnerables avec son nombre de CVE et leur severite.
      - Classe-les par severite (CRITICAL > HIGH > MEDIUM > LOW).
   B. SECRETS POTENTIELS DETECTES
      - Liste chaque finding avec le fichier, le numero de ligne, et le type de secret.
      - Rappelle que ces findings doivent etre audites manuellement.
   C. CONCLUSION SECURITE
      - Score de risque : ELEVE / MOYEN / FAIBLE (base sur le nombre et la severite).

Ne fais PAS de recommandations de remediation ici — c'est le role du Reporter Agent.
Ne tente jamais d'halluciner des donnees que tu n'as pas obtenues via les tools.
""",
    tools=[security_toolset],
)
