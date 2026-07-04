"""
CodeSleuth - Root orchestrator.
Sequential pipeline: Scanner -> Analyst -> Security -> Reporter -> Critic.

Note: SequentialAgent is marked as "deprecated" in the ADK docs in favor of a future
"Workflow" type, but the latter is not yet available in the current package.
SequentialAgent remains the correct API to use for now; the warning it displays
is harmless.
"""

from google.adk.agents import SequentialAgent
from codesleuth.agents.scanner_agent import scanner_agent
from codesleuth.agents.analyst_agent import analyst_agent
from codesleuth.agents.security_agent import security_agent
from codesleuth.agents.reporter_agent import reporter_agent
from codesleuth.agents.critic_agent import critic_agent

root_agent = SequentialAgent(
    name="codesleuth_orchestrator",
    description=(
        "Audits a GitHub repository: structure scan, code quality analysis, "
        "security audit, final technical debt report, and coherence validation."
    ),
    sub_agents=[
        scanner_agent,
        analyst_agent,
        security_agent,
        reporter_agent,
        critic_agent,
    ],
)