"""
CodeSleuth - Point d'entree racine.
Pipeline sequentiel : Scanner -> Analyst -> Security -> Reporter.

Note : SequentialAgent est marque "deprecated" dans la doc ADK au profit d'un futur
"Workflow", mais ce dernier n'est pas encore livre dans le package actuel.
SequentialAgent reste donc la bonne API a utiliser pour l'instant, le warning
qu'il affiche est inoffensif.
"""

from google.adk.agents import SequentialAgent
from codesleuth.agents.scanner_agent import scanner_agent
from codesleuth.agents.analyst_agent import analyst_agent
from codesleuth.agents.security_agent import security_agent
from codesleuth.agents.reporter_agent import reporter_agent

root_agent = SequentialAgent(
    name="codesleuth_orchestrator",
    description=(
        "Audite un repo GitHub : scan de structure, analyse qualite du code, "
        "audit de securite, puis rapport complet de dette technique."
    ),
    sub_agents=[
        scanner_agent,
        analyst_agent,
        security_agent,
        reporter_agent,
    ],
)