"""
CodeSleuth - Outils d'analyse de code (utilisés par l'Analyst Agent)
Chaque fonction est volontairement simple et déterministe : pas de LLM ici,
juste des heuristiques mesurables. C'est le LLM de l'Analyst Agent qui
interprétera et priorisera ensuite ces résultats bruts.
"""

import ast
import ast as _ast  # évite un ombrage accidentel du nom "ast" dans les fonctions


def detect_long_functions(source_code: str, threshold: int = 50) -> dict:
    """
    Détecte les fonctions Python trop longues (dépassant `threshold` lignes).
    Retourne une liste de {name, lines, lineno}.
    Ne fonctionne que sur du code Python valide (syntaxe correcte).
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return {"error": f"Code Python invalide, impossible de parser : {e}"}

    long_funcs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            length = end - node.lineno
            if length > threshold:
                long_funcs.append({
                    "name": node.name,
                    "lines": length,
                    "lineno": node.lineno,
                })
    return {"long_functions": long_funcs, "threshold_used": threshold}


def count_todos_and_fixmes(source_code: str) -> dict:
    """
    Compte les occurrences de TODO / FIXME / XXX dans le code.
    Un nombre élevé indique du travail non terminé accumulé.
    """
    markers = ["TODO", "FIXME", "XXX"]
    counts = {m: source_code.count(m) for m in markers}
    total = sum(counts.values())
    return {"counts": counts, "total": total}


def check_documentation_ratio(source_code: str) -> dict:
    """
    Calcule le pourcentage de fonctions qui ont une docstring.
    Un ratio bas indique un code mal documenté, plus difficile à maintenir.
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return {"error": f"Code Python invalide, impossible de parser : {e}"}

    functions = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if not functions:
        return {"documentation_ratio": None, "total_functions": 0}

    documented = sum(1 for f in functions if ast.get_docstring(f) is not None)
    ratio = round(documented / len(functions) * 100, 1)
    return {
        "documentation_ratio_percent": ratio,
        "total_functions": len(functions),
        "documented_functions": documented,
    }


def analyze_complexity(source_code: str, threshold: int = 10) -> dict:
    """
    Calcule la complexité cyclomatique de chaque fonction via radon.
    Une complexité > threshold indique une fonction difficile à tester et à maintenir.
    """
    try:
        from radon.complexity import cc_visit
    except ImportError:
        return {"error": "radon n'est pas installé (uv add radon)"}

    try:
        results = cc_visit(source_code)
    except SyntaxError as e:
        return {"error": f"Code Python invalide, impossible de parser : {e}"}

    complex_funcs = [
        {"name": r.name, "complexity": r.complexity, "lineno": r.lineno}
        for r in results if r.complexity > threshold
    ]
    return {"complex_functions": complex_funcs, "threshold_used": threshold}


def detect_code_duplication_simple(source_code_a: str, source_code_b: str) -> dict:
    """
    Détection SIMPLE de duplication entre deux fichiers : compare les lignes
    non vides normalisées (sans indentation) et calcule un pourcentage de recouvrement.
    Ce n'est pas un détecteur AST sophistiqué, volontairement simple pour rester rapide.
    """
    lines_a = {l.strip() for l in source_code_a.splitlines() if l.strip()}
    lines_b = {l.strip() for l in source_code_b.splitlines() if l.strip()}

    if not lines_a or not lines_b:
        return {"similarity_percent": 0, "note": "un des fichiers est vide"}

    common = lines_a & lines_b
    similarity = round(len(common) / min(len(lines_a), len(lines_b)) * 100, 1)
    return {"similarity_percent": similarity, "common_lines": len(common)}