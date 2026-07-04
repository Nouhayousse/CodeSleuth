# -*- coding: utf-8 -*-
"""
CodeSleuth - Security Patterns (Senior Security Reviewer)
==========================================================
Deterministic static analysis — no LLM needed for these detections.

Five capabilities:
  1. scan_dangerous_patterns   : Dangerous APIs and patterns (Python + Java)
  2. analyze_attack_surface    : Attack surface estimation
  3. detect_security_smells    : Composite security anti-patterns
  4. map_to_owasp              : OWASP Top 10 mapping
  5. compute_security_score    : Explained security score (0..30)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ===========================================================================
# FEATURE 1 — Dangerous API & Security Pattern Detection
# ===========================================================================

@dataclass
class DangerousPattern:
    id: str
    language: str          # "python" | "java" | "any"
    regex: str             # pattern to search (compiled lazily)
    severity: str          # "Critical" | "High" | "Medium" | "Low"
    title: str
    risk: str
    remediation: str
    owasp: str             # e.g. "A03:Injection"

    def compile(self) -> re.Pattern:
        return re.compile(self.regex, re.IGNORECASE | re.MULTILINE)


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

DANGEROUS_PATTERNS: list[DangerousPattern] = [

    # ── Python ──────────────────────────────────────────────────────────────

    DangerousPattern(
        id="PY-001", language="python",
        regex=r"\beval\s*\(",
        severity="Critical",
        title="eval() — Arbitrary Code Execution",
        risk="eval() executes a string as Python code. An attacker controlling the input can execute arbitrary code on the server.",
        remediation="Replace with ast.literal_eval() for safe parsing of literals, or refactor the logic to avoid dynamic evaluation.",
        owasp="A03:Injection",
    ),
    DangerousPattern(
        id="PY-002", language="python",
        regex=r"\bexec\s*\(",
        severity="Critical",
        title="exec() — Arbitrary Code Execution",
        risk="exec() dynamically executes Python code blocks. Equivalent to eval() but for entire code blocks.",
        remediation="Eliminate the use of exec(). If dynamic plugin loading is required, use importlib with validated modules.",
        owasp="A03:Injection",
    ),
    DangerousPattern(
        id="PY-003", language="python",
        regex=r"\bsubprocess\b.*\bshell\s*=\s*True",
        severity="Critical",
        title="subprocess(shell=True) — OS Command Injection",
        risk="shell=True passes the command string to the system shell (/bin/sh). If user inputs are concatenated, it leads to OS Command Injection.",
        remediation="Use subprocess with arguments passed as a list and set shell=False (e.g., subprocess.run(['ls', '-la'], shell=False)).",
        owasp="A03:Injection",
    ),
    DangerousPattern(
        id="PY-004", language="python",
        regex=r"\bpickle\.loads?\s*\(",
        severity="High",
        title="pickle.load() — Unsafe Deserialization",
        risk="pickle serialized data can contain arbitrary executable payloads. Deserializing untrusted data leads to arbitrary code execution (RCE).",
        remediation="Use safer serialization formats like JSON, Protocol Buffers, or MessagePack for untrusted network input.",
        owasp="A08:Software and Data Integrity Failures",
    ),
    DangerousPattern(
        id="PY-005", language="python",
        regex=r"\byaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*yaml\.SafeLoader)",
        severity="High",
        title="yaml.load() without SafeLoader — Unsafe Deserialization",
        risk="yaml.load() without specifying a safe loader (yaml.SafeLoader) can instantiate arbitrary Python objects, leading to arbitrary code execution.",
        remediation="Use yaml.safe_load() or explicitly specify yaml.load(data, Loader=yaml.SafeLoader).",
        owasp="A08:Software and Data Integrity Failures",
    ),
    DangerousPattern(
        id="PY-006", language="python",
        regex=r"\bhashlib\.md5\s*\(",
        severity="Medium",
        title="hashlib.md5() — Weak Cryptographic Hash",
        risk="MD5 is cryptographically broken and vulnerable to collision attacks. It should not be used for security-sensitive purposes like signatures or password hashing.",
        remediation="Upgrade to hashlib.sha256() or hashlib.sha3_256(). For password storage, use argon2, bcrypt, or pbkdf2.",
        owasp="A02:Cryptographic Failures",
    ),
    DangerousPattern(
        id="PY-007", language="python",
        regex=r"\bhashlib\.sha1\s*\(",
        severity="Medium",
        title="hashlib.sha1() — Weak Cryptographic Hash",
        risk="SHA-1 is no longer secure against well-funded collision attacks. It should be deprecated for security uses.",
        remediation="Migrate to SHA-256 or SHA-3 for all cryptographic signatures and integrity checks.",
        owasp="A02:Cryptographic Failures",
    ),
    DangerousPattern(
        id="PY-008", language="python",
        regex=r"\bos\.system\s*\(",
        severity="High",
        title="os.system() — OS Command Execution",
        risk="os.system() executes command strings in a subshell, making it vulnerable to shell injection if user inputs are formatted directly.",
        remediation="Replace with subprocess.run() or subprocess.Popen() with shell=False and pass arguments as a list.",
        owasp="A03:Injection",
    ),
    DangerousPattern(
        id="PY-009", language="python",
        regex=r"\btempfile\.mktemp\s*\(",
        severity="Low",
        title="tempfile.mktemp() — File Creation Race Condition (TOCTOU)",
        risk="mktemp() returns a temporary file path without creating the file. An attacker could create a file at that path before the program does.",
        remediation="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() which create the file securely and atomically.",
        owasp="A01:Broken Access Control",
    ),
    DangerousPattern(
        id="PY-010", language="python",
        regex=r"\b__import__\s*\(",
        severity="High",
        title="__import__() — Dynamic Module Import",
        risk="Dynamically importing modules based on user inputs can allow attackers to import arbitrary modules and execute their initialization code.",
        remediation="Use importlib.import_module() and validate inputs against a strict whitelist of allowed modules.",
        owasp="A03:Injection",
    ),

    # ── Java ────────────────────────────────────────────────────────────────

    DangerousPattern(
        id="JV-001", language="java",
        regex=r"Runtime\.getRuntime\(\)\.exec\s*\(",
        severity="Critical",
        title="Runtime.exec() — OS Command Injection",
        risk="Executing system commands directly in Java exposes the application to command injection if user inputs are concatenated.",
        remediation="Replace with ProcessBuilder and pass arguments as an explicit array or list, never concatenating user strings.",
        owasp="A03:Injection",
    ),
    DangerousPattern(
        id="JV-002", language="java",
        regex=r"\bnew\s+ProcessBuilder\s*\(",
        severity="High",
        title="ProcessBuilder — External Process Execution",
        risk="ProcessBuilder spawns OS processes. If the command array is built using untrusted input, shell injection may occur.",
        remediation="Thoroughly validate and sanitize all command line parameters. Use safer library APIs instead of spawning system shells.",
        owasp="A03:Injection",
    ),
    DangerousPattern(
        id="JV-003", language="java",
        regex=r"(?:Statement\b.*(?:executeQuery|executeUpdate|execute)\s*\(|(?:executeQuery|executeUpdate|execute)\s*\([^)]*\+)",
        severity="Critical",
        title="SQL Statement — Potential SQL Injection",
        risk="Using java.sql.Statement with concatenated query strings is the primary vector for SQL injection. Attackers can read, modify, or delete database tables.",
        remediation="Replace with PreparedStatement and bind parameters using placeholders (?). Never concatenate untrusted strings into SQL queries.",
        owasp="A03:Injection",
    ),
    DangerousPattern(
        id="JV-004", language="java",
        regex=r"\bnew\s+ObjectInputStream\s*\(",
        severity="High",
        title="ObjectInputStream — Unsafe Java Deserialization",
        risk="Java deserialization is a critical attack vector. Deserializing untrusted data can trigger gadget chains leading to Remote Code Execution (RCE).",
        remediation="Migrate to safer data exchange formats like JSON or Protobuf. If standard Java deserialization is required, apply a strict ObjectInputFilter.",
        owasp="A08:Software and Data Integrity Failures",
    ),
    DangerousPattern(
        id="JV-005", language="java",
        regex=r"\bClass\.forName\s*\(",
        severity="High",
        title="Class.forName() — Dynamic Class Loading",
        risk="Loading classes dynamically from user-supplied names allows attackers to instantiate arbitrary classes, potentially executing static initializers.",
        remediation="Restrict dynamic loading to a strict whitelist of known class names, never passing user input directly.",
        owasp="A03:Injection",
    ),
    DangerousPattern(
        id="JV-006", language="java",
        regex=r"\.setAccessible\s*\(\s*true\s*\)",
        severity="Medium",
        title="setAccessible(true) — Access Control Bypass",
        risk="Bypasses Java access controls (private/protected). Often used in reflection-based exploits and deserialization payloads. Signals poor architecture.",
        remediation="Refactor the code to avoid reflection-based access. Utilize Java modules (JPMS) to enforce clean encapsulation boundaries.",
        owasp="A01:Broken Access Control",
    ),
    DangerousPattern(
        id="JV-007", language="java",
        regex=r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']",
        severity="Medium",
        title="MD5 — Weak Cryptographic Hash",
        risk="MD5 is vulnerable to collision attacks and no longer secure for signatures, hashes, or checksums.",
        remediation="Upgrade to SHA-256 or SHA-3. For passwords, use BCrypt, PBKDF2, or Argon2.",
        owasp="A02:Cryptographic Failures",
    ),
    DangerousPattern(
        id="JV-008", language="java",
        regex=r"MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']",
        severity="Medium",
        title="SHA-1 — Weak Cryptographic Hash",
        risk="SHA-1 is mathematically broken for digital signatures and data integrity verification due to collision vulnerabilities.",
        remediation="Migrate to SHA-256 or SHA-3.",
        owasp="A02:Cryptographic Failures",
    ),
    DangerousPattern(
        id="JV-009", language="java",
        regex=r"(?:\"DES\"|\"DESede\"|Cipher\.getInstance\s*\([^)]*\"DES)",
        severity="High",
        title="DES/3DES — Deprecated Cipher Algorithm",
        risk="DES (56-bit key) is broken. 3DES is officially deprecated due to susceptibility to Sweet32 collision attacks.",
        remediation="Upgrade to AES (AES-256-GCM or AES-256-CBC with secure IV).",
        owasp="A02:Cryptographic Failures",
    ),
    DangerousPattern(
        id="JV-010", language="java",
        regex=r"\.disableCsrf\(\)|csrf\(\)\.disable\(\)",
        severity="Critical",
        title="Disabled CSRF Protection",
        risk="Disabling CSRF exposes state-changing requests to Cross-Site Request Forgery attacks. Logged-in users can be coerced into performing unwanted actions.",
        remediation="Keep CSRF protection enabled. For stateless REST APIs, use JWT tokens passed via Bearer headers instead of session cookies.",
        owasp="A01:Broken Access Control",
    ),
    DangerousPattern(
        id="JV-011", language="java",
        regex=r"\bnew\s+Random\s*\(\)",
        severity="Medium",
        title="new Random() — Insecure PRNG",
        risk="java.util.Random is predictable and insecure. It should never be used for security tokens, keys, salts, or passwords.",
        remediation="Use java.security.SecureRandom for generating cryptographically secure random values.",
        owasp="A02:Cryptographic Failures",
    ),
    DangerousPattern(
        id="JV-012", language="java",
        regex=r"createStatement\s*\(\s*\)|prepareStatement\s*\(\s*[\"'][^\"']*\+",
        severity="High",
        title="Dynamic SQL Construction",
        risk="Building SQL statements using string concatenation or formatting (even inside prepareStatement) bypasses parameterized bindings, enabling SQL Injection.",
        remediation="Exclusively use parameterized queries with PreparedStatement and bind inputs using placeholders (?). Use ORM frameworks.",
        owasp="A03:Injection",
    ),
]

# Extension -> language mapping
_EXT_LANG = {
    ".py": "python",
    ".java": "java",
    ".kt": "java",
    ".groovy": "java",
}

def _detect_language(filepath: str) -> str:
    for ext, lang in _EXT_LANG.items():
        if filepath.endswith(ext):
            return lang
    return "any"


def scan_dangerous_patterns(
    filepath: str,
    source_code: str,
) -> list[dict]:
    """
    Scans a source file looking for dangerous API usage and code patterns.

    Returns:
        List of findings, each containing:
        {id, file, line, severity, title, risk, remediation, owasp, snippet}
    """
    language = _detect_language(filepath)
    findings = []
    lines = source_code.splitlines()

    for pattern in DANGEROUS_PATTERNS:
        if pattern.language not in (language, "any"):
            continue
        compiled = pattern.compile()
        for lineno, line in enumerate(lines, start=1):
            if compiled.search(line):
                findings.append({
                    "id": pattern.id,
                    "file": filepath,
                    "line": lineno,
                    "severity": pattern.severity,
                    "title": pattern.title,
                    "risk": pattern.risk,
                    "remediation": pattern.remediation,
                    "owasp": pattern.owasp,
                    "snippet": line.strip()[:160],
                })
                break  # one finding per pattern per file is sufficient

    return findings


# ===========================================================================
# FEATURE 2 — Attack Surface Analysis
# ===========================================================================

_ATTACK_SURFACE_PATTERNS: dict[str, list[str]] = {
    "rest_endpoints": [
        # Python
        r"@app\.(?:route|get|post|put|delete|patch)\s*\(",
        r"@router\.(?:get|post|put|delete|patch)\s*\(",
        r"@api_view\s*\(",
        r"path\s*\(['\"]",
        r"url\s*\(['\"]",
        # Java
        r"@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*",
        r"@(?:GET|POST|PUT|DELETE|PATCH)\s*$",
        r"@Path\s*\(['\"]",
    ],
    "controllers": [
        r"@Controller\b", r"@RestController\b",
        r"class\s+\w+Controller\b",
        r"class\s+\w+View\b",
        r"class\s+\w+Handler\b",
        r"Blueprint\s*\(",
    ],
    "auth_modules": [
        r"@login_required", r"@requires_auth", r"@authenticated",
        r"UserDetails\b", r"AuthenticationProvider\b",
        r"SecurityConfig\b", r"WebSecurityConfigurer\b",
        r"class\s+\w*Auth\w*\b", r"class\s+\w*Login\w*\b",
        r"jwt\.decode\s*\(", r"verify_token\s*\(",
    ],
    "file_uploads": [
        r"request\.files\b", r"file\.save\s*\(", r"\.upload\s*\(",
        r"MultipartFile\b", r"MultipartHttpServletRequest\b",
        r"@RequestPart\b", r"\.transferTo\s*\(",
        r"UploadedFile\b",
    ],
    "db_access": [
        r"\.execute\s*\(['\"]?\s*(?:SELECT|INSERT|UPDATE|DELETE)",
        r"Session\.query\s*\(", r"Model\.objects\.", r"\.filter\s*\(",
        r"EntityManager\b", r"JpaRepository\b", r"CrudRepository\b",
        r"@Repository\b", r"DataSource\b",
        r"\.query\s*\(", r"connection\.cursor\s*\(",
    ],
    "template_engines": [
        r"render_template\s*\(", r"\.render\s*\(['\"].*\.html",
        r"Velocity(?:Engine|Template)\b", r"FreeMarker\b",
        r"ThymeleafDialect\b", r"\.jsp['\"]",
        r"jinja2\.", r"Jinja2\b",
        r"Template\s*\(['\"]",
    ],
    "websockets": [
        r"@ServerEndpoint\b", r"WebSocketHandler\b",
        r"websocket\.WebSocket\b", r"websockets\.connect\s*\(",
        r"flask_socketio\b", r"SocketIO\s*\(",
        r"SockJS\b",
    ],
}


def analyze_attack_surface(
    file_list: list[dict],
) -> dict:
    """
    Analyzes the attack surface of a repository.

    Returns:
        {
          "counts": {category: int},
          "files_by_category": {category: [filepath]},
          "rating": "LOW" | "MEDIUM" | "HIGH",
          "explanation": str
        }
    """
    counts: dict[str, int] = {cat: 0 for cat in _ATTACK_SURFACE_PATTERNS}
    files_by_category: dict[str, list[str]] = {cat: [] for cat in _ATTACK_SURFACE_PATTERNS}

    compiled = {
        cat: [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]
        for cat, patterns in _ATTACK_SURFACE_PATTERNS.items()
    }

    for file_entry in file_list:
        path = file_entry.get("path", "")
        content = file_entry.get("content", "")
        if not content:
            continue

        for cat, patterns in compiled.items():
            for pattern in patterns:
                if pattern.search(content):
                    counts[cat] += 1
                    if path not in files_by_category[cat]:
                        files_by_category[cat].append(path)
                    break

    total_surface = sum(counts.values())
    rest = counts.get("rest_endpoints", 0)
    auth = counts.get("auth_modules", 0)
    db = counts.get("db_access", 0)
    uploads = counts.get("file_uploads", 0)

    if total_surface == 0:
        rating = "LOW"
        explanation = "No major attack surface components detected (pure library or local utility)."
    elif rest >= 10 or (rest >= 5 and db >= 3) or uploads >= 3:
        rating = "HIGH"
        explanation = (
            f"Significant attack surface detected with {rest} REST endpoints, {db} database access points, "
            f"and {uploads} file uploads. Requires thorough review."
        )
    elif rest >= 3 or db >= 2 or auth >= 2:
        rating = "MEDIUM"
        explanation = (
            f"Moderate attack surface detected with {rest} REST endpoints, {db} database access points, "
            f"and {auth} authentication configurations."
        )
    else:
        rating = "LOW"
        explanation = (
            f"Limited attack surface with only {total_surface} sensitive components identified."
        )

    return {
        "counts": counts,
        "files_by_category": files_by_category,
        "rating": rating,
        "explanation": explanation,
        "total_surface_indicators": total_surface,
    }


# ===========================================================================
# FEATURE 3 — Security Smells
# ===========================================================================

@dataclass
class SecuritySmell:
    severity: str   # "High" | "Medium" | "Low"
    title: str
    detail: str
    file: Optional[str] = None


def detect_security_smells(
    file_list: list[dict],
    dangerous_findings: list[dict],
    attack_surface: dict,
) -> list[dict]:
    """
    Identifies composite security anti-patterns (security smells).

    Returns:
        List of smells [{severity, title, detail, file?}]
    """
    smells: list[SecuritySmell] = []
    _seen = set()

    def add(smell: SecuritySmell):
        key = (smell.title, smell.file)
        if key not in _seen:
            _seen.add(key)
            smells.append(smell)

    for file_entry in file_list:
        path = file_entry.get("path", "")
        content = file_entry.get("content", "")
        if not content:
            continue
        line_count = len(content.splitlines())

        # God Security Object
        is_security_file = any(
            kw in path.lower()
            for kw in ("auth", "security", "login", "permission", "access", "token", "session")
        )
        if is_security_file and line_count > 500:
            add(SecuritySmell(
                severity="Medium",
                title="God Security Object",
                detail=f"Security file '{path}' is very large ({line_count} lines). "
                       f"Overloaded security modules are difficult to audit and prone to flaws.",
                file=path,
            ))

        # Legacy template engines
        legacy_engines = [
            (r"velocity\b|\.vm[\"']", "Velocity"),
            (r"freemarker\b|\.ftl[\"']", "FreeMarker"),
            (r"\bjsp\b|\.jsp[\"']", "JSP"),
            (r"struts\b", "Apache Struts"),
        ]
        for pattern, name in legacy_engines:
            if re.search(pattern, content, re.IGNORECASE):
                add(SecuritySmell(
                    severity="Medium",
                    title=f"Legacy Template Engine: {name}",
                    detail=f"Legacy rendering engine '{name}' detected in '{path}'. "
                           f"Older engines have a history of XSS and SSTI vulnerabilities.",
                    file=path,
                ))
                break

        # Dynamic SQL construction
        dyn_sql = re.findall(
            r"[\"']SELECT[^\"']*[\"']\s*\+|\.format\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE)",
            content, re.IGNORECASE
        )
        if dyn_sql:
            add(SecuritySmell(
                severity="High",
                title="Dynamic SQL Construction",
                detail=f"Raw SQL queries constructed via concatenation or string formatting in '{path}'. "
                       f"High risk of SQL injection outside parameterized queries.",
                file=path,
            ))

        # Disabled security mechanisms
        if re.search(r"\.permitAll\(\)|\.anonymous\(\)|antMatchers\([^)]*\)\.permitAll", content):
            add(SecuritySmell(
                severity="High",
                title="Disabled Security Access Control",
                detail=f"Explicit bypass of access control detected in '{path}'. "
                       f"Verify that permitAll() does not expose sensitive administration routes.",
                file=path,
            ))

        # Excessive reflection
        reflect_count = len(re.findall(r"\.setAccessible\(true\)|Class\.forName\(|getDeclaredMethod", content))
        if reflect_count >= 3:
            add(SecuritySmell(
                severity="Medium",
                title="Excessive Reflection Usage",
                detail=f"{reflect_count} dynamic reflection calls detected in '{path}'. "
                       f"Forced access increases attack surface and hinders static code auditing.",
                file=path,
            ))

    # Global cross-file checks
    crypto_findings = [f for f in dangerous_findings if f.get("owasp") == "A02:Cryptographic Failures"]
    if len(crypto_findings) >= 3:
        smells.append(SecuritySmell(
            severity="High",
            title="Density of Weak Cryptography",
            detail=f"{len(crypto_findings)} instances of weak cryptography (MD5, SHA-1, DES, Random) "
                   f"scattered across files. Indicates systemic security debt.",
        ))

    surface = attack_surface.get("counts", {})
    if surface.get("file_uploads", 0) >= 2 and surface.get("rest_endpoints", 0) >= 5:
        smells.append(SecuritySmell(
            severity="High",
            title="Concentrated Attack Surface Danger",
            detail=f"High density of file uploads ({surface['file_uploads']}) "
                   f"combined with web endpoints ({surface['rest_endpoints']}). "
                   f"A single vulnerability in upload handlers could lead to Remote Code Execution.",
        ))

    return [
        {
            "severity": s.severity,
            "title": s.title,
            "detail": s.detail,
            "file": s.file,
        }
        for s in smells
    ]


# ===========================================================================
# FEATURE 4 — OWASP Top 10 Mapping
# ===========================================================================

OWASP_CATEGORIES = {
    "A01:Broken Access Control": {
        "label": "A01 — Broken Access Control",
        "description": "Insufficient restrictions on authenticated users, allowing privilege escalation.",
    },
    "A02:Cryptographic Failures": {
        "label": "A02 — Cryptographic Failures",
        "description": "Sensitive data exposure due to weak cryptographic choices or hardcoded secrets.",
    },
    "A03:Injection": {
        "label": "A03 — Injection",
        "description": "SQL, OS command, or dynamic code execution via unvalidated inputs.",
    },
    "A04:Insecure Design": {
        "label": "A04 — Insecure Design",
        "description": "Flaws in architecture, threat modeling, and baseline security patterns.",
    },
    "A05:Security Misconfiguration": {
        "label": "A05 — Security Misconfiguration",
        "description": "Default configs, open debug ports, or disabled security features.",
    },
    "A06:Vulnerable Components": {
        "label": "A06 — Vulnerable and Outdated Components",
        "description": "Third-party libraries with known CVE vulnerabilities.",
    },
    "A07:Auth Failures": {
        "label": "A07 — Identification and Authentication Failures",
        "description": "Session fixation, weak passwords, or lack of multi-factor authentication.",
    },
    "A08:Software and Data Integrity Failures": {
        "label": "A08 — Software and Data Integrity Failures",
        "description": "Unsafe deserialization or lack of checksum verification in updates.",
    },
    "A09:Logging Failures": {
        "label": "A09 — Security Logging and Monitoring Failures",
        "description": "Lack of security logging to detect, track, and alert on active breaches.",
    },
    "A10:SSRF": {
        "label": "A10 — Server-Side Request Forgery",
        "description": "Web server coerced into requesting arbitrary internal or external URLs.",
    },
}


def map_to_owasp(
    dangerous_findings: list[dict],
    cve_count: int,
    secret_count: int,
    smells: list[dict],
) -> dict:
    """
    Maps security findings to the OWASP Top 10 (2021).

    Returns:
        Dict category_id -> {label, description, findings, status}
    """
    coverage: dict[str, dict] = {}

    for cat_id, cat_info in OWASP_CATEGORIES.items():
        coverage[cat_id] = {
            "label": cat_info["label"],
            "description": cat_info["description"],
            "findings": [],
            "status": "No evidence found.",
        }

    for finding in dangerous_findings:
        cat_id = finding.get("owasp")
        if cat_id and cat_id in coverage:
            coverage[cat_id]["findings"].append({
                "type": "Detected",
                "source": f"[{finding['id']}] {finding['title']} — {finding['file']}:{finding['line']}",
            })

    if cve_count > 0:
        coverage["A06:Vulnerable Components"]["findings"].append({
            "type": "Confirmed",
            "source": f"{cve_count} CVE(s) detected in dependencies via OSV.dev.",
        })

    if secret_count > 0:
        coverage["A02:Cryptographic Failures"]["findings"].append({
            "type": "Suspicious",
            "source": f"{secret_count} potential secrets exposed in source files.",
        })

    for smell in smells:
        title = smell.get("title", "")
        if "disable" in title.lower() or "csrf" in title.lower() or "bypass" in title.lower():
            coverage["A05:Security Misconfiguration"]["findings"].append({
                "type": "Suspicious",
                "source": f"Security Smell: {title}",
            })
        elif "God" in title or "density" in title.lower():
            coverage["A04:Insecure Design"]["findings"].append({
                "type": "Manual Review Recommended",
                "source": f"Security Smell: {title}",
            })

    coverage["A09:Logging Failures"]["findings"].append({
        "type": "Manual Review Recommended",
        "source": "Security logging coverage cannot be fully validated via static pattern matching.",
    })

    coverage["A10:SSRF"]["findings"].append({
        "type": "Manual Review Recommended",
        "source": "Verify that outgoing HTTP requests do not process arbitrary, unvalidated user URLs.",
    })

    for cat_id, cat_data in coverage.items():
        findings = cat_data["findings"]
        if not findings:
            cat_data["status"] = "No evidence found."
        else:
            confirmed = [f for f in findings if f["type"] == "Confirmed"]
            detected = [f for f in findings if f["type"] == "Detected"]
            if confirmed:
                cat_data["status"] = f"{len(confirmed)} confirmed finding(s)."
            elif detected:
                cat_data["status"] = f"{len(detected)} dangerous pattern(s) detected — review recommended."
            else:
                cat_data["status"] = "Manual review recommended."

    return coverage


# ===========================================================================
# FEATURE 5 — Explainable Security Score
# ===========================================================================

def compute_security_score(
    cve_count: int,
    cve_critical: int,
    secret_count: int,
    dangerous_findings: list[dict],
    smells: list[dict],
    attack_surface: dict,
    has_active_maintenance: bool = False,
    has_tests: bool = False,
) -> dict:
    """
    Calculates a security score out of 30 points.

    Returns:
        {
          "score": int,
          "max_score": 30,
          "risk": str,
          "positive_factors": [str],
          "negative_factors": [str],
          "explanation": str
        }
    """
    score = 30
    positive: list[str] = []
    negative: list[str] = []

    # ── Bonuses ─────────────────────────────────────────────────────────────

    if has_active_maintenance:
        positive.append("Active maintenance (recent commits)")

    if has_tests:
        positive.append("Tests present (reduces regression risk)")

    if cve_count == 0 and secret_count == 0 and not dangerous_findings:
        positive.append("No vulnerabilities, secrets, or dangerous patterns detected")

    if cve_count == 0:
        positive.append("No known CVEs in dependencies")

    if secret_count == 0:
        positive.append("No exposed secrets in source code")

    # ── Deductions ──────────────────────────────────────────────────────────

    if cve_critical > 0:
        deduct = min(cve_critical * 5, 15)
        score -= deduct
        negative.append(f"{cve_critical} Critical CVE(s) in dependencies (−{deduct} pts)")

    cve_other = cve_count - cve_critical
    if cve_other > 0:
        deduct = min(cve_other * 2, 6)
        score -= deduct
        negative.append(f"{cve_other} non-critical CVE(s) in dependencies (−{deduct} pts)")

    if secret_count > 0:
        deduct = min(secret_count * 3, 9)
        score -= deduct
        negative.append(f"{secret_count} potential secrets exposed (−{deduct} pts)")

    critical_patterns = [f for f in dangerous_findings if f.get("severity") == "Critical"]
    high_patterns = [f for f in dangerous_findings if f.get("severity") == "High"]
    med_patterns = [f for f in dangerous_findings if f.get("severity") == "Medium"]

    if critical_patterns:
        deduct = min(len(critical_patterns) * 4, 12)
        score -= deduct
        negative.append(f"{len(critical_patterns)} Critical API pattern(s) detected (−{deduct} pts)")

    if high_patterns:
        deduct = min(len(high_patterns) * 2, 6)
        score -= deduct
        negative.append(f"{len(high_patterns)} High-risk API pattern(s) detected (−{deduct} pts)")

    if med_patterns:
        deduct = min(len(med_patterns), 3)
        score -= deduct
        negative.append(f"{len(med_patterns)} Medium-risk API pattern(s) detected (−{deduct} pts)")

    high_smells = [s for s in smells if s.get("severity") == "High"]
    med_smells = [s for s in smells if s.get("severity") == "Medium"]

    if high_smells:
        deduct = min(len(high_smells) * 2, 4)
        score -= deduct
        negative.append(f"{len(high_smells)} High-severity security smell(s) (−{deduct} pts)")

    if med_smells:
        deduct = min(len(med_smells), 2)
        score -= deduct
        negative.append(f"{len(med_smells)} Medium-severity security smell(s) (−{deduct} pts)")

    surface_rating = attack_surface.get("rating", "LOW")
    if surface_rating == "HIGH":
        score -= 3
        negative.append("Significant attack surface exposure (−3 pts)")
    elif surface_rating == "MEDIUM":
        score -= 1
        negative.append("Moderate attack surface exposure (−1 pt)")

    score = max(0, min(30, score))

    if score >= 25:
        risk = "LOW"
    elif score >= 17:
        risk = "MEDIUM"
    elif score >= 10:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    if negative:
        explanation = (
            f"Final Score: {score}/30 — Risk level: {risk}. "
            f"{len(positive)} positive factor(s) and {len(negative)} negative factor(s) identified. "
            f"Prioritize remediation of Critical severity findings."
        )
    else:
        explanation = (
            f"Final Score: {score}/30 — Risk level: {risk}. "
            f"No significant security findings detected via static analysis. "
            f"Manual verification remains recommended."
        )

    return {
        "score": score,
        "max_score": 30,
        "risk": risk,
        "positive_factors": positive,
        "negative_factors": negative,
        "explanation": explanation,
    }
