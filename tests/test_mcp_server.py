"""
Test du serveur MCP en isolation : lance le serveur en subprocess et
appelle ses tools via un client MCP, sans passer par ADK.

Usage: python test_mcp_server.py
"""

import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["codesleuth/mcp/github_mcp_server.py"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Liste les tools exposés par le serveur
            tools = await session.list_tools()
            print(f"Serveur MCP demarre. Tools disponibles: {[t.name for t in tools.tools]}")

            # Appelle get_repo_structure sur votre repo
            print("\n--- Test get_repo_structure ---")
            result = await session.call_tool(
                "get_repo_structure",
                arguments={"owner": "Nouhayousse", "repo": "learn_RAG"},
            )
            print("Resultat get_repo_structure obtenu.")

            # Appelle scan_github_repository
            print("\n--- Test scan_github_repository ---")
            result_scan = await session.call_tool(
                "scan_github_repository",
                arguments={"owner": "Nouhayousse", "repo": "learn_RAG"},
            )
            print("Resultat scan_github_repository obtenu.")
            
            # Appelle analyze_repo_files
            print("\n--- Test analyze_repo_files ---")
            result_analysis = await session.call_tool(
                "analyze_repo_files",
                arguments={
                    "owner": "Nouhayousse",
                    "repo": "learn_RAG",
                    "filepaths": ["rag_test.py"]
                },
            )
            print("Resultat analyze_repo_files obtenu.")

            # Appelle analyze_repo_security_deep
            print("\n--- Test analyze_repo_security_deep ---")
            result_deep = await session.call_tool(
                "analyze_repo_security_deep",
                arguments={
                    "owner": "Nouhayousse",
                    "repo": "learn_RAG",
                    "filepaths": ["rag_test.py"]
                },
            )
            print("Resultat analyze_repo_security_deep obtenu.")
            import json
            print(json.dumps(result_deep.content[0].text if hasattr(result_deep, 'content') else str(result_deep), indent=2))


if __name__ == "__main__":
    asyncio.run(main())