"""
CodeSleuth - Scanner Agent MCP Server
Expose des outils pour scanner un repo GitHub public : structure de fichiers,
fichiers de dépendances, activité de commits.
"""

import os
import sys
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from github import Github, Auth, GithubException

# Ajoute la racine du workspace au chemin de recherche pour pouvoir importer codesleuth
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from codesleuth.tools.code_analysis import (
    detect_long_functions,
    count_todos_and_fixmes,
    check_documentation_ratio,
    analyze_complexity,
    detect_code_duplication_simple,
)
from codesleuth.tools.osv_tools import analyze_repo_security as _analyze_repo_security

load_dotenv()

mcp = FastMCP("codesleuth-github-scanner")
gh = Github(auth=Auth.Token(os.getenv("GITHUB_TOKEN")))


@mcp.tool()
def get_repo_structure(owner: str, repo: str) -> dict:
    """
    Retourne la liste complète des fichiers du repo avec taille et chemin.
    Utilise l'API Git Trees pour récupérer toute la structure en un seul appel.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repo introuvable ou inaccessible : {e}"}

    try:
        tree = r.get_git_tree(r.default_branch, recursive=True)
        files = []
        for element in tree.tree:
            if element.type == "blob":
                files.append({
                    "path": element.path,
                    "size_bytes": element.size,
                    "extension": element.path.split(".")[-1] if "." in element.path else None,
                })
    except GithubException as e:
        return {"error": f"Impossible de récupérer l'arborescence Git : {e}"}

    return {
        "repo": f"{owner}/{repo}",
        "default_branch": r.default_branch,
        "total_files": len(files),
        "files": files,
        "has_tests_folder": any("test" in f["path"].lower() for f in files),
        "stars": r.stargazers_count,
        "language": r.language,
    }


@mcp.tool()
def scan_github_repository(owner: str, repo: str) -> dict:
    """
    Scanne globalement un repo GitHub public en une seule fois.
    Retourne la structure complète des fichiers, les dépendances (si trouvées), et l'activité récente.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repo introuvable ou inaccessible : {e}"}

    # 1. Structure
    try:
        tree = r.get_git_tree(r.default_branch, recursive=True)
        files = []
        for element in tree.tree:
            if element.type == "blob":
                files.append({
                    "path": element.path,
                    "size_bytes": element.size,
                    "extension": element.path.split(".")[-1] if "." in element.path else None,
                })
    except GithubException as e:
        return {"error": f"Impossible de récupérer l'arborescence Git : {e}"}

    # 2. Dépendances
    dependency_info = {"error": "Aucun fichier de dépendances standard trouvé"}
    candidates = ["requirements.txt", "package.json", "pom.xml", "pyproject.toml"]
    for filename in candidates:
        try:
            content_file = r.get_contents(filename)
            decoded = content_file.decoded_content.decode("utf-8")
            dependency_info = {"filename": filename, "content": decoded}
            break
        except GithubException:
            continue

    # 3. Activité
    try:
        commits = r.get_commits()
        recent = commits[:50]
        recent_list = list(recent)
        activity_info = {
            "last_commit_date": str(recent_list[0].commit.author.date) if recent_list else None,
            "last_commit_message": recent_list[0].commit.message if recent_list else None,
            "sample_size": len(recent_list),
        }
    except GithubException as e:
        activity_info = {"error": f"Impossible de récupérer l'activité : {e}"}

    return {
        "repo": f"{owner}/{repo}",
        "default_branch": r.default_branch,
        "total_files": len(files),
        "files": files,
        "has_tests_folder": any("test" in f["path"].lower() for f in files),
        "stars": r.stargazers_count,
        "language": r.language,
        "dependency_file": dependency_info,
        "commit_activity": activity_info,
    }


@mcp.tool()
def get_file_content(owner: str, repo: str, filepath: str) -> dict:
    """
    Récupère le contenu texte d'un fichier spécifique du repo.
    Utilisé par l'Analyst Agent pour analyser le code source.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
        content_file = r.get_contents(filepath)
        decoded = content_file.decoded_content.decode("utf-8", errors="ignore")
        return {"path": filepath, "content": decoded, "size": len(decoded)}
    except GithubException as e:
        return {"error": f"Impossible de lire {filepath} : {e}"}
    except UnicodeDecodeError:
        return {"error": f"{filepath} n'est pas un fichier texte (binaire ?)"}


@mcp.tool()
def analyze_repo_files(owner: str, repo: str, filepaths: list[str]) -> dict:
    """
    Télécharge et analyse une liste de fichiers Python dans le repo.
    Applique la complexité, longueur de fonctions, documentation, TODOs,
    et la duplication de code entre eux.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repo introuvable ou inaccessible : {e}"}

    file_contents = {}
    analysis_results = {}

    for filepath in filepaths:
        try:
            content_file = r.get_contents(filepath)
            decoded = content_file.decoded_content.decode("utf-8", errors="ignore")
            file_contents[filepath] = decoded
            
            # Run the 4 basic metrics
            long_funcs = detect_long_functions(decoded)
            complexity = analyze_complexity(decoded)
            todos = count_todos_and_fixmes(decoded)
            doc_ratio = check_documentation_ratio(decoded)
            
            analysis_results[filepath] = {
                "size_bytes": len(decoded),
                "long_functions": long_funcs,
                "complexity": complexity,
                "todos_and_fixmes": todos,
                "documentation_ratio": doc_ratio,
            }
        except GithubException as e:
            analysis_results[filepath] = {"error": f"Impossible de lire le fichier : {e}"}
        except Exception as e:
            analysis_results[filepath] = {"error": f"Erreur lors de l'analyse : {e}"}

    # Duplication calculation if 2 or more files
    duplication_results = []
    if len(filepaths) >= 2:
        for i in range(len(filepaths)):
            for j in range(i + 1, len(filepaths)):
                file_a = filepaths[i]
                file_b = filepaths[j]
                if file_a in file_contents and file_b in file_contents:
                    dup = detect_code_duplication_simple(file_contents[file_a], file_contents[file_b])
                    duplication_results.append({
                        "file_a": file_a,
                        "file_b": file_b,
                        "similarity_percent": dup.get("similarity_percent"),
                        "common_lines": dup.get("common_lines"),
                    })

    return {
        "repo": f"{owner}/{repo}",
        "analysis": analysis_results,
        "duplication": duplication_results,
    }


@mcp.tool()
def get_dependency_file(owner: str, repo: str) -> dict:
    """
    Cherche et retourne le contenu du fichier de dépendances du projet
    (requirements.txt, package.json, pom.xml...).
    """
    candidates = ["requirements.txt", "package.json", "pom.xml", "pyproject.toml"]
    r = gh.get_repo(f"{owner}/{repo}")

    for filename in candidates:
        try:
            content_file = r.get_contents(filename)
            decoded = content_file.decoded_content.decode("utf-8")
            return {"filename": filename, "content": decoded}
        except GithubException:
            continue

    return {"error": "Aucun fichier de dépendances standard trouvé"}


@mcp.tool()
def get_commit_activity(owner: str, repo: str) -> dict:
    """
    Retourne des métriques d'activité : dernier commit, nombre de commits récents.
    Utilisé pour détecter les projets/fichiers potentiellement abandonnés.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
        commits = r.get_commits()
        recent = commits[:50]  # on limite pour éviter de consommer le rate limit
        recent_list = list(recent)

        return {
            "last_commit_date": str(recent_list[0].commit.author.date) if recent_list else None,
            "last_commit_message": recent_list[0].commit.message if recent_list else None,
            "sample_size": len(recent_list),
        }
    except GithubException as e:
        return {"error": f"Impossible de récupérer l'activité : {e}"}



@mcp.tool()
def analyze_repo_security(
    owner: str,
    repo: str,
    filepaths: list[str] | None = None,
) -> dict:
    """
    Analyse de securite consolidee d'un repo GitHub.
    Verifie les vulnerabilites OSV.dev des dependances PyPI et detecte
    les secrets potentiels (regex) dans les fichiers source.

    Args:
        owner    : Proprietaire du repo (ex: "google").
        repo     : Nom du repo (ex: "adk-python").
        filepaths: Optionnel — liste de chemins de fichiers a scanner pour
                   les secrets. Si absent, les .py du repo sont utilises.
    """
    return _analyze_repo_security(owner=owner, repo=repo, filepaths=filepaths)


if __name__ == "__main__":
    mcp.run()