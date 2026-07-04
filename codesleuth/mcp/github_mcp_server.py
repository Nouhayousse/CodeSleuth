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
    compute_hotspot_score,
)
from codesleuth.tools.osv_tools import analyze_repo_security as _analyze_repo_security
from codesleuth.tools.security_patterns import (
    scan_dangerous_patterns,
    analyze_attack_surface,
    detect_security_smells,
    map_to_owasp,
    compute_security_score,
)

load_dotenv()

mcp = FastMCP("codesleuth-github-scanner")
gh = Github(auth=Auth.Token(os.getenv("GITHUB_TOKEN")))


@mcp.tool()
def get_repo_structure(owner: str, repo: str) -> dict:
    """
    Returns the complete list of files in the repository with size and path.
    Uses the Git Trees API to fetch the full tree structure in a single call.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repository not found or inaccessible: {e}"}

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
        return {"error": f"Unable to retrieve Git tree: {e}"}

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
    Scans a public GitHub repository globally in a single call.
    Returns the complete file structure, dependencies (if found), and recent commit activity.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repository not found or inaccessible: {e}"}

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
        return {"error": f"Unable to retrieve Git tree: {e}"}

    # 2. Dependencies
    dependency_info = {"error": "No standard dependency file found"}
    candidates = ["requirements.txt", "package.json", "pom.xml", "pyproject.toml"]
    for filename in candidates:
        try:
            content_file = r.get_contents(filename)
            decoded = content_file.decoded_content.decode("utf-8")
            dependency_info = {"filename": filename, "content": decoded}
            break
        except GithubException:
            continue

    # 3. Activity
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
        activity_info = {"error": f"Unable to retrieve commit activity: {e}"}

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
    Retrieves the raw text content of a specific file in the repository.
    Used by the Analyst Agent to analyze source code.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
        content_file = r.get_contents(filepath)
        decoded = content_file.decoded_content.decode("utf-8", errors="ignore")
        return {"path": filepath, "content": decoded, "size": len(decoded)}
    except GithubException as e:
        return {"error": f"Unable to read {filepath}: {e}"}
    except UnicodeDecodeError:
        return {"error": f"{filepath} is not a text file (binary?)"}


@mcp.tool()
def analyze_repo_files(owner: str, repo: str, filepaths: list[str]) -> dict:
    """
    Downloads and analyzes a list of Python files in the repository.
    Computes cyclomatic complexity, function length, documentation, TODOs,
    and code duplication among them.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repository not found or inaccessible: {e}"}

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
            analysis_results[filepath] = {"error": f"Unable to read file: {e}"}
        except Exception as e:
            analysis_results[filepath] = {"error": f"Error during analysis: {e}"}

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
    Finds and returns the content of the project's dependency file
    (requirements.txt, package.json, pom.xml, pyproject.toml, etc.).
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

    return {"error": "No standard dependency file found"}


@mcp.tool()
def get_commit_activity(owner: str, repo: str) -> dict:
    """
    Returns repository commit activity metrics: last commit date, recent commit counts.
    Used to identify inactive or abandoned projects and files.
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
        commits = r.get_commits()
        recent = commits[:50]  # cap to avoid rate limits
        recent_list = list(recent)

        return {
            "last_commit_date": str(recent_list[0].commit.author.date) if recent_list else None,
            "last_commit_message": recent_list[0].commit.message if recent_list else None,
            "sample_size": len(recent_list),
        }
    except GithubException as e:
        return {"error": f"Unable to retrieve commit activity: {e}"}



@mcp.tool()
def analyze_repo_security(
    owner: str,
    repo: str,
    filepaths: list[str] | None = None,
) -> dict:
    """
    Consolidated security analysis of a GitHub repository.
    Checks PyPI ecosystem dependencies against OSV.dev for CVEs and
    scans source files using regular expressions to detect secrets.

    Args:
        owner    : Repository owner (e.g., "google").
        repo     : Repository name (e.g., "adk-python").
        filepaths: Optional list of file paths to scan for secrets.
                   If empty, detects python source files.
    """
    return _analyze_repo_security(owner=owner, repo=repo, filepaths=filepaths)



@mcp.tool()
def analyze_repo_security_deep(
    owner: str,
    repo: str,
    filepaths: list[str] | None = None,
) -> dict:
    """
    Analyse de securite APPROFONDIE d'un repo GitHub (Senior Security Reviewer).
    Integre en un seul appel :
      - Detection CVE via OSV.dev (existant)
      - Detection de secrets (existant)
      - APIs et patterns dangereux (Python + Java)
      - Surface d'attaque (REST, auth, DB, uploads, websockets)
      - Security smells composites
      - Mapping OWASP Top 10
      - Score de securite explique (0..30)

    Args:
        owner    : Proprietaire du repo (ex: "pallets").
        repo     : Nom du repo (ex: "flask").
        filepaths: Optionnel — fichiers source a analyser. Si absent, auto-detecte.
    """
    from github import Github, Auth, GithubException
    import os

    token = os.getenv("GITHUB_TOKEN")
    _gh = Github(auth=Auth.Token(token)) if token else Github()

    try:
        r = _gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repo introuvable ou inaccessible : {e}"}

    # ── 1. Analyse de base (CVE + secrets) ─────────────────────────────────
    base_result = _analyze_repo_security(owner=owner, repo=repo, filepaths=filepaths)
    if "error" in base_result:
        return base_result

    total_cves = base_result.get("total_vulnerabilities", 0)
    total_secrets = base_result.get("total_secret_findings", 0)

    # Count critical CVEs
    critical_cves = 0
    for dep in base_result.get("dependency_vulnerabilities", []):
        for vuln in dep.get("vulnerabilities", []):
            if vuln.get("severity") == "Critique":
                critical_cves += 1

    # ── 2. Collecte des fichiers source pour l'analyse statique ────────────
    MAX_DEEP_FILES = 20
    SUPPORTED_EXTENSIONS = (".py", ".java", ".kt", ".groovy", ".js", ".ts")

    files_to_analyze: list[str] = []
    if filepaths:
        files_to_analyze = filepaths[:MAX_DEEP_FILES]
    else:
        try:
            tree = r.get_git_tree(r.default_branch, recursive=True)
            candidates = [
                e.path for e in tree.tree
                if e.type == "blob"
                and any(e.path.endswith(ext) for ext in SUPPORTED_EXTENSIONS)
                and "test" not in e.path.lower()
                and ".venv" not in e.path
                and "vendor" not in e.path
                and "node_modules" not in e.path
            ]
            candidates.sort(key=lambda p: (p.count("/"), p))
            files_to_analyze = candidates[:MAX_DEEP_FILES]
        except GithubException as e:
            files_to_analyze = []

    # ── 3. Telechargement + analyse statique de chaque fichier ─────────────
    file_contents: list[dict] = []
    all_dangerous_findings: list[dict] = []

    for filepath in files_to_analyze:
        try:
            content_file = r.get_contents(filepath)
            source = content_file.decoded_content.decode("utf-8", errors="ignore")
            file_contents.append({"path": filepath, "content": source})
            findings = scan_dangerous_patterns(filepath, source)
            all_dangerous_findings.extend(findings)
        except GithubException:
            pass
        except Exception:
            pass

    # ── 4. Attack surface ───────────────────────────────────────────────────
    # Also include file metadata from the full tree for attack surface
    full_file_list = file_contents
    try:
        tree = r.get_git_tree(r.default_branch, recursive=True)
        # For attack surface, we use the files we already fetched
    except Exception:
        pass

    attack_surface = analyze_attack_surface(full_file_list)

    # ── 5. Security smells ──────────────────────────────────────────────────
    smells = detect_security_smells(
        file_list=file_contents,
        dangerous_findings=all_dangerous_findings,
        attack_surface=attack_surface,
    )

    # ── 6. OWASP mapping ───────────────────────────────────────────────────
    owasp_coverage = map_to_owasp(
        dangerous_findings=all_dangerous_findings,
        cve_count=total_cves,
        secret_count=total_secrets,
        smells=smells,
    )

    # ── 7. Score explique ──────────────────────────────────────────────────
    has_tests = any(
        "test" in e.path.lower()
        for e in (r.get_git_tree(r.default_branch, recursive=True).tree
                  if True else [])
    ) if True else False
    try:
        tree_check = r.get_git_tree(r.default_branch, recursive=True)
        has_tests = any("test" in e.path.lower() for e in tree_check.tree)
    except Exception:
        has_tests = False

    commit_activity = base_result.get("commit_activity", {})
    has_active_maintenance = bool(
        base_result.get("total_vulnerabilities") is not None  # proxy: repo accessible
    )

    security_score = compute_security_score(
        cve_count=total_cves,
        cve_critical=critical_cves,
        secret_count=total_secrets,
        dangerous_findings=all_dangerous_findings,
        smells=smells,
        attack_surface=attack_surface,
        has_active_maintenance=has_active_maintenance,
        has_tests=has_tests,
    )

    # ── 8. Résultat unifié ─────────────────────────────────────────────────
    return {
        "repo": f"{owner}/{repo}",
        # ── Analyse de base ──
        "dependency_file_scanned": base_result.get("dependency_file_scanned", "aucun"),
        "packages_checked": base_result.get("packages_checked", 0),
        "dependency_vulnerabilities": base_result.get("dependency_vulnerabilities", []),
        "secret_findings": base_result.get("secret_findings", []),
        "total_vulnerabilities": total_cves,
        "total_secret_findings": total_secrets,
        "vulnerable_packages": base_result.get("vulnerable_packages", []),
        # ── Analyse approfondie ──
        "files_analyzed": files_to_analyze,
        "dangerous_api_findings": all_dangerous_findings,
        "attack_surface": attack_surface,
        "security_smells": smells,
        "owasp_coverage": owasp_coverage,
        "security_score": security_score,
        # ── Summary ──
        "summary": (
            f"Deep security analysis of {owner}/{repo}: "
            f"{total_cves} CVE(s), {total_secrets} secret(s), "
            f"{len(all_dangerous_findings)} dangerous API(s), "
            f"{len(smells)} security smell(s). "
            f"Security score: {security_score['score']}/30 — Risk level: {security_score['risk']}."
        ),
    }


@mcp.tool()
def get_file_commit_frequency(
    owner: str,
    repo: str,
    filepath: str,
    days: int = 90,
) -> dict:
    """
    Returns the number of commits that touched a specific file over the last `days` days.
    Use this to determine file churn (how frequently a file is changed).
    Only call on 2-4 files already selected for quality analysis — do not bulk-call.

    Args:
        owner   : Repository owner (e.g., "pallets").
        repo    : Repository name (e.g., "flask").
        filepath: Path to the file (e.g., "src/app.py").
        days    : Look-back window in days (default: 90).
    """
    from datetime import datetime, timezone, timedelta

    try:
        r = gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repository not found or inaccessible: {e}"}

    since = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        commits = r.get_commits(path=filepath, since=since)
        commit_list = list(commits[:100])  # cap at 100 to respect rate limits
        last_modified = None
        if commit_list:
            last_modified = str(commit_list[0].commit.author.date)
        return {
            "filepath": filepath,
            "commit_count": len(commit_list),
            "period_days": days,
            "last_modified": last_modified,
        }
    except GithubException as e:
        return {"error": f"Unable to retrieve commit history for {filepath}: {e}"}


@mcp.tool()
def analyze_file_with_hotspot(
    owner: str,
    repo: str,
    filepath: str,
) -> dict:
    """
    All-in-one quality + hotspot analysis for a single source file.
    Combines static code metrics (complexity, long functions, todos, doc ratio)
    with commit frequency to calculate a hotspot score.

    A high hotspot score = complex AND frequently changed = high regression risk.

    Args:
        owner   : Repository owner (e.g., "google").
        repo    : Repository name (e.g., "adk-python").
        filepath: Path to the source file (e.g., "src/core/agent.py").
    """
    try:
        r = gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repository not found or inaccessible: {e}"}

    # Step 1 — Download the file content
    try:
        content_file = r.get_contents(filepath)
        source = content_file.decoded_content.decode("utf-8", errors="ignore")
    except GithubException as e:
        return {"error": f"Unable to read {filepath}: {e}"}

    # Step 2 — Static analysis metrics
    long_funcs = detect_long_functions(source)
    complexity_result = analyze_complexity(source)
    todos = count_todos_and_fixmes(source)
    doc_ratio = check_documentation_ratio(source)

    # Step 3 — Extract max complexity score (for hotspot calculation)
    complex_funcs = complexity_result.get("complex_functions", [])
    if complex_funcs:
        max_complexity = max(f["complexity"] for f in complex_funcs)
        max_complexity_func = max(complex_funcs, key=lambda f: f["complexity"])
    else:
        # No function exceeded the threshold; use total function count as proxy
        # radon: run without threshold to get all functions
        try:
            from radon.complexity import cc_visit
            all_results = cc_visit(source)
            if all_results:
                max_complexity = max(r.complexity for r in all_results)
                max_complexity_func = {
                    "name": max(all_results, key=lambda r: r.complexity).name,
                    "complexity": max_complexity,
                    "lineno": max(all_results, key=lambda r: r.complexity).lineno,
                }
            else:
                max_complexity = 1
                max_complexity_func = None
        except Exception:
            max_complexity = 1
            max_complexity_func = None

    # Step 4 — Commit frequency (churn)
    churn = get_file_commit_frequency(owner, repo, filepath, days=90)
    commit_count = churn.get("commit_count", 0)

    # Step 5 — Hotspot score
    hotspot = compute_hotspot_score(max_complexity, commit_count)

    return {
        "repo": f"{owner}/{repo}",
        "filepath": filepath,
        "size_bytes": len(source),
        # Static quality metrics
        "long_functions": long_funcs,
        "complexity": complexity_result,
        "max_complexity": max_complexity,
        "max_complexity_function": max_complexity_func,
        "todos_and_fixmes": todos,
        "documentation_ratio": doc_ratio,
        # Churn (commit frequency)
        "commit_frequency": churn,
        # Hotspot synthesis
        "hotspot": hotspot,
        "hotspot_interpretation": (
            f"'{filepath}' has a hotspot score of {hotspot['hotspot_score']} "
            f"(complexity={max_complexity} × {commit_count} commits in 90 days). "
            f"Risk level: {hotspot['risk_level']}."
        ),
    }


if __name__ == "__main__":
    mcp.run()