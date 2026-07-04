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
        return {"error": f"Timeout during OSV.dev request for {package_name}"}
    except httpx.HTTPStatusError as e:
        return {"error": f"OSV.dev HTTP error: {e.response.status_code}"}
    except Exception as e:
        return {"error": f"Unexpected OSV.dev error: {e}"}

    vulns = data.get("vulns", [])
    simplified = []
    for v in vulns:
        simplified.append({
            "id": v.get("id"),
            "summary": v.get("summary", "No summary available"),
            "severity": _extract_severity(v),
            "published": v.get("published", "?"),
            "aliases": v.get("aliases", []),
        })

    return {
        "package": package_name,
        "ecosystem": ecosystem,
        "version": version or "not specified",
        "vulnerabilities": simplified,
        "vuln_count": len(simplified),
    }


def _extract_score_from_dict(d) -> float | None:
    if isinstance(d, dict):
        for key in ["score", "cvss_score", "cvss3_score", "cvss2_score"]:
            if key in d:
                val = d[key]
                try:
                    return float(val)
                except (ValueError, TypeError):
                    pass
        for k, v in d.items():
            if "score" in k.lower() or "cvss" in k.lower():
                if isinstance(v, (int, float)):
                    return float(v)
                if isinstance(v, str):
                    try:
                        return float(v)
                    except ValueError:
                        pass
            if isinstance(v, (dict, list)):
                res = _extract_score_from_dict(v)
                if res is not None:
                    return res
    elif isinstance(d, list):
        for item in d:
            res = _extract_score_from_dict(item)
            if res is not None:
                return res
    return None


def _extract_label_from_dict(d) -> str | None:
    if isinstance(d, dict):
        if "severity" in d:
            val = d["severity"]
            if isinstance(val, str) and val.strip():
                return val.strip()
        for k, v in d.items():
            if "severity" in k.lower() or "level" in k.lower() or "priority" in k.lower():
                if isinstance(v, str) and v.strip():
                    return v.strip()
            if isinstance(v, (dict, list)):
                res = _extract_label_from_dict(v)
                if res is not None:
                    return res
    elif isinstance(d, list):
        for item in d:
            res = _extract_label_from_dict(item)
            if res is not None:
                return res
    return None


def _extract_score_from_text(vuln_entry: dict) -> float | None:
    text_parts = []
    for field in ["summary", "details", "description"]:
        val = vuln_entry.get(field)
        if isinstance(val, str):
            text_parts.append(val)
    text = " ".join(text_parts)
    if not text:
        return None
    matches = re.findall(
        r'(?:cvss|score|severite|severity|base\s+score)[^.0-9]*\b(10\.0|[0-9]\.[0-9])\b',
        text,
        re.IGNORECASE
    )
    if matches:
        try:
            return float(matches[0])
        except ValueError:
            pass
    return None


def _extract_severity(vuln_entry: dict) -> str:
    """
    Extracts the CVSS score from the OSV vulnerability entry
    and converts it to a qualitative label (Critical, High, Medium, Low).
    In fallback, searches for a direct label (database_specific.severity).
    """
    # 1. Search for a structured numerical score
    score = _extract_score_from_dict(vuln_entry)
    
    # 2. Search for a numerical score in textual descriptions
    if score is None:
        score = _extract_score_from_text(vuln_entry)
        
    # 3. Convert score to label
    if score is not None:
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
            
    # 4. Fallback: search for a qualitative text label
    label = _extract_label_from_dict(vuln_entry)
    if label:
        label_upper = label.upper()
        if "CRITICAL" in label_upper or "CRITIQUE" in label_upper:
            return "Critical"
        elif "HIGH" in label_upper or "ÉLEVÉE" in label_upper or "ELEVEE" in label_upper:
            return "High"
        elif "MEDIUM" in label_upper or "MODERATE" in label_upper or "MOYENNE" in label_upper or "MOYEN" in label_upper:
            return "Medium"
        elif "LOW" in label_upper or "FAIBLE" in label_upper:
            return "Low"
            
    return "Unknown"



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
        return {"error": f"Repository not found or inaccessible: {e}"}

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
            secret_results.append({"error": f"Unable to list repository files: {e}"})

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
        f"Security analysis for {owner}/{repo}: "
        f"{total_vulns} OSV vulnerability(ies) found in {len(vulnerable_packages)} package(s), "
        f"{total_secrets} potential secret(s) detected in {len(files_to_scan)} file(s)."
    )

    return {
        "repo": f"{owner}/{repo}",
        "dependency_file_scanned": dep_filename or "none",
        "packages_checked": len(dep_results),
        "dependency_vulnerabilities": dep_results,
        "files_scanned_for_secrets": files_to_scan,
        "secret_findings": secret_results,
        "total_vulnerabilities": total_vulns,
        "total_secret_findings": total_secrets,
        "vulnerable_packages": vulnerable_packages,
        "summary": summary,
    }

