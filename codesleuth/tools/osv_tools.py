"""
CodeSleuth - Outils de Sécurité (Security Agent)
Deux responsabilités :
  1. check_vulnerabilities   : interroge api.osv.dev pour une dépendance donnée.
  2. detect_potential_secrets: scanne du code source avec des regex pour trouver
                               des clés/secrets exposés accidentellement.
  3. analyze_repo_security   : outil consolidé appelé par le Security Agent —
                               une seule invocation, un seul rapport.
"""

import re
import httpx
from github import Github, Auth, GithubException
import os

# ---------------------------------------------------------------------------
# Patterns de détection de secrets (regex)
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[tuple[str, str]] = [
    ("AWS Access Key ID",       r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Access Key",   r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Generic API Key",         r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"),
    ("Generic Bearer Token",    r"(?i)bearer\s+[a-zA-Z0-9\-\._~\+/]+=*"),
    ("Private RSA Key Header",  r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("GitHub Personal Token",   r"ghp_[a-zA-Z0-9]{36}"),
    ("Slack Bot Token",         r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}"),
    ("Google API Key",          r"AIza[0-9A-Za-z\\-_]{35}"),
    ("Stripe Secret Key",       r"sk_live_[0-9a-zA-Z]{24}"),
    ("Generic Password",        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
]


# ---------------------------------------------------------------------------
# 1. Vérification OSV.dev
# ---------------------------------------------------------------------------

def check_vulnerabilities(
    package_name: str,
    ecosystem: str = "PyPI",
    version: str | None = None,
) -> dict:
    """
    Interroge l'API OSV.dev pour récupérer les vulnérabilités connues
    d'un paquet donné.

    Args:
        package_name: Nom du paquet (ex: "requests").
        ecosystem   : Écosystème du gestionnaire (ex: "PyPI", "npm").
        version     : Version à vérifier (optionnel — si absente, renvoie
                      toutes les CVE pour ce paquet).

    Returns:
        dict avec "package", "ecosystem", "version", "vulnerabilities" (liste),
        "vuln_count", ou "error".
    """
    payload: dict = {
        "package": {"name": package_name, "ecosystem": ecosystem}
    }
    if version:
        payload["version"] = version

    try:
        resp = httpx.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=10.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.TimeoutException:
        return {"error": f"Timeout lors de la requete OSV.dev pour {package_name}"}
    except httpx.HTTPStatusError as e:
        return {"error": f"Erreur HTTP OSV.dev : {e.response.status_code}"}
    except Exception as e:
        return {"error": f"Erreur inattendue OSV.dev : {e}"}

    vulns = data.get("vulns", [])
    simplified = []
    for v in vulns:
        simplified.append({
            "id": v.get("id"),
            "summary": v.get("summary", "Pas de resume disponible"),
            "severity": _extract_severity(v),
            "published": v.get("published", "?"),
            "aliases": v.get("aliases", []),
        })

    return {
        "package": package_name,
        "ecosystem": ecosystem,
        "version": version or "non specifie",
        "vulnerabilities": simplified,
        "vuln_count": len(simplified),
    }


def _extract_severity(vuln_entry: dict) -> str:
    """Extrait la sévérité depuis severity[], database_specific, ou 'UNKNOWN'."""
    severity_list = vuln_entry.get("severity", [])
    for s in severity_list:
        score = s.get("score", "")
        if "CRITICAL" in score.upper():
            return "CRITICAL"
        if "HIGH" in score.upper():
            return "HIGH"
        if "MEDIUM" in score.upper():
            return "MEDIUM"
        if "LOW" in score.upper():
            return "LOW"
    # Fallback: database_specific CVSS
    db_specific = vuln_entry.get("database_specific", {})
    cvss = db_specific.get("cvss", {})
    if isinstance(cvss, dict):
        base_score = cvss.get("score", 0)
        if base_score >= 9.0:
            return "CRITICAL"
        if base_score >= 7.0:
            return "HIGH"
        if base_score >= 4.0:
            return "MEDIUM"
        if base_score > 0:
            return "LOW"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# 2. Détection de secrets par regex
# ---------------------------------------------------------------------------

def detect_potential_secrets(source_code: str, filepath: str = "<unknown>") -> dict:
    """
    Scanne du code source avec des regex pour identifier des secrets potentiels
    (clés API, mots de passe, tokens JWT, clés RSA…).

    Args:
        source_code: Contenu textuel du fichier à analyser.
        filepath   : Chemin du fichier (pour l'affichage dans le rapport).

    Returns:
        dict avec "filepath", "findings" (liste de matches), "finding_count".
    """
    findings = []
    lines = source_code.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for pattern_name, pattern in SECRET_PATTERNS:
            if re.search(pattern, line):
                # On masque la valeur dans le rapport pour ne pas l'exposer davantage
                sanitized = re.sub(r"['\"][^'\"]{4,}['\"]", "'***MASKED***'", line.strip())
                findings.append({
                    "pattern": pattern_name,
                    "lineno": line_no,
                    "snippet": sanitized[:200],  # max 200 chars
                })
                break  # un seul match par ligne suffit

    return {
        "filepath": filepath,
        "findings": findings,
        "finding_count": len(findings),
    }


# ---------------------------------------------------------------------------
# 3. Outil consolidé : analyse de sécurité complète d'un repo
# ---------------------------------------------------------------------------

def _parse_requirements(content: str) -> list[tuple[str, str | None]]:
    """
    Parse un requirements.txt ou pyproject.toml pour extraire (nom, version).
    Retourne une liste de tuples (package_name, version_or_None).
    """
    packages = []
    for line in content.splitlines():
        line = line.strip()
        # Ignorer commentaires et lignes vides
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Gérer les extras entre crochets : requests[security]>=2.28
        line = re.sub(r"\[.*?\]", "", line)
        # Séparer nom et version
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!~^]{1,2})\s*([\d\.\*]+)", line)
        if match:
            pkg, _op, ver = match.group(1), match.group(2), match.group(3)
            # On ne passe que les versions exactes (==) ou première version (>=)
            packages.append((pkg, ver if _op in ("==", "~=") else None))
        else:
            # Pas de version spécifiée
            simple = re.match(r"^([a-zA-Z0-9_\-\.]+)", line)
            if simple:
                packages.append((simple.group(1), None))
    return packages


def analyze_repo_security(
    owner: str,
    repo: str,
    filepaths: list[str] | None = None,
    max_deps: int = 20,
    max_files: int = 10,
) -> dict:
    """
    Outil consolidé du Security Agent.
    Effectue en un seul appel :
      a) Téléchargement du fichier de dépendances + vérification OSV.dev
         pour les N premières dépendances PyPI.
      b) Scan de secrets regex sur les filepaths fournis (ou les .py du repo).

    Args:
        owner    : Propriétaire du repo GitHub (ex: "google").
        repo     : Nom du repo (ex: "adk-python").
        filepaths: Liste optionnelle de fichiers à scanner pour les secrets.
                   Si None, les .py listés dans le repo (max max_files) sont utilisés.
        max_deps : Nombre maximum de dépendances à vérifier (évite le rate-limit OSV).
        max_files: Nombre maximum de fichiers à scanner pour les secrets.

    Returns:
        dict contenant :
          - "dependency_vulnerabilities" : [{package, vuln_count, vulns, ...}]
          - "secret_findings"            : [{filepath, findings, finding_count}]
          - "summary"                    : résumé textuel
    """
    token = os.getenv("GITHUB_TOKEN")
    gh = Github(auth=Auth.Token(token)) if token else Github()

    dep_results: list[dict] = []
    secret_results: list[dict] = []

    # ---- a) Vérification des dépendances via OSV.dev ----
    dep_content = None
    dep_filename = None
    candidates = ["requirements.txt", "pyproject.toml", "package.json"]

    try:
        r = gh.get_repo(f"{owner}/{repo}")
    except GithubException as e:
        return {"error": f"Repo introuvable ou inaccessible : {e}"}

    for filename in candidates:
        try:
            content_file = r.get_contents(filename)
            dep_content = content_file.decoded_content.decode("utf-8", errors="ignore")
            dep_filename = filename
            break
        except GithubException:
            continue

    if dep_content and dep_filename in ("requirements.txt", "pyproject.toml"):
        packages = _parse_requirements(dep_content)[:max_deps]
        for pkg_name, pkg_version in packages:
            vuln_data = check_vulnerabilities(pkg_name, "PyPI", pkg_version)
            dep_results.append(vuln_data)

    # ---- b) Scan de secrets dans les fichiers source ----
    files_to_scan: list[str] = []

    if filepaths:
        files_to_scan = filepaths[:max_files]
    else:
        # Auto-détection : prendre les .py du repo (hors tests/vendored)
        try:
            tree = r.get_git_tree(r.default_branch, recursive=True)
            py_files = [
                e.path for e in tree.tree
                if e.type == "blob"
                and e.path.endswith(".py")
                and "test" not in e.path.lower()
                and ".venv" not in e.path
                and "vendor" not in e.path
            ]
            # Prioriser les fichiers à la racine du package
            py_files.sort(key=lambda p: (p.count("/"), p))
            files_to_scan = py_files[:max_files]
        except GithubException as e:
            secret_results.append({"error": f"Impossible de lister les fichiers : {e}"})

    for filepath in files_to_scan:
        try:
            content_file = r.get_contents(filepath)
            source = content_file.decoded_content.decode("utf-8", errors="ignore")
            result = detect_potential_secrets(source, filepath)
            secret_results.append(result)
        except GithubException as e:
            secret_results.append({"filepath": filepath, "error": str(e), "finding_count": 0})
        except Exception as e:
            secret_results.append({"filepath": filepath, "error": str(e), "finding_count": 0})

    # ---- c) Résumé ----
    total_vulns = sum(d.get("vuln_count", 0) for d in dep_results if "error" not in d)
    total_secrets = sum(s.get("finding_count", 0) for s in secret_results if "error" not in s)
    vulnerable_packages = [
        d["package"] for d in dep_results
        if d.get("vuln_count", 0) > 0
    ]

    summary = (
        f"Analyse de securite de {owner}/{repo} : "
        f"{total_vulns} vulnerabilite(s) OSV trouvee(s) dans {len(vulnerable_packages)} paquet(s), "
        f"{total_secrets} secret(s) potentiel(s) detecte(s) dans {len(files_to_scan)} fichier(s)."
    )

    return {
        "repo": f"{owner}/{repo}",
        "dependency_file_scanned": dep_filename or "aucun",
        "packages_checked": len(dep_results),
        "dependency_vulnerabilities": dep_results,
        "files_scanned_for_secrets": files_to_scan,
        "secret_findings": secret_results,
        "total_vulnerabilities": total_vulns,
        "total_secret_findings": total_secrets,
        "vulnerable_packages": vulnerable_packages,
        "summary": summary,
    }
