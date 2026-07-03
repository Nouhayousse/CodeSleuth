"""
Tests unitaires pour les outils d'analyse de code (code_analysis.py).
Teste : complexite cyclomatique, longueur de fonctions, documentation,
        TODOs, et detection de duplication simple.
"""

import pytest
from codesleuth.tools.code_analysis import (
    detect_long_functions,
    count_todos_and_fixmes,
    check_documentation_ratio,
    analyze_complexity,
    detect_code_duplication_simple,
)

# ---------------------------------------------------------------------------
# Fixtures de code source
# ---------------------------------------------------------------------------

SIMPLE_CODE = """
def short_func():
    return 42
"""

LONG_FUNC_CODE = "\n".join(["def big_function():"] + ["    x = 1" for _ in range(55)])

COMPLEX_CODE = """
def complex_func(a, b, c):
    if a:
        if b:
            for i in range(10):
                if c:
                    if i > 5:
                        while True:
                            if a > b:
                                break
                            a += 1
    return a
"""

DOCUMENTED_CODE = """
def func_with_doc():
    \"\"\"Cette fonction a une docstring.\"\"\"
    return 1

def func_without_doc():
    return 2

def another_documented():
    \"\"\"Aussi documentee.\"\"\"
    pass
"""

TODO_CODE = """
# TODO: fix this
x = 1  # FIXME: bad approach
# XXX: temporary hack
# TODO: another one
"""

DUPLICATE_A = """
def shared():
    return 1
common_line = True
another = "hello"
"""

DUPLICATE_B = """
def shared():
    return 1
common_line = True
unique_line = False
"""


# ---------------------------------------------------------------------------
# Tests : detect_long_functions
# ---------------------------------------------------------------------------

class TestDetectLongFunctions:
    def test_short_function_not_flagged(self):
        result = detect_long_functions(SIMPLE_CODE)
        assert "long_functions" in result
        assert len(result["long_functions"]) == 0

    def test_long_function_detected(self):
        result = detect_long_functions(LONG_FUNC_CODE, threshold=50)
        assert len(result["long_functions"]) == 1
        assert result["long_functions"][0]["name"] == "big_function"
        assert result["long_functions"][0]["lines"] > 50

    def test_threshold_respected(self):
        result = detect_long_functions(LONG_FUNC_CODE, threshold=100)
        assert len(result["long_functions"]) == 0

    def test_invalid_python_returns_error(self):
        result = detect_long_functions("def broken(:\n    pass")
        assert "error" in result


# ---------------------------------------------------------------------------
# Tests : count_todos_and_fixmes
# ---------------------------------------------------------------------------

class TestCountTodosAndFixmes:
    def test_counts_correctly(self):
        result = count_todos_and_fixmes(TODO_CODE)
        assert result["counts"]["TODO"] == 2
        assert result["counts"]["FIXME"] == 1
        assert result["counts"]["XXX"] == 1
        assert result["total"] == 4

    def test_no_markers(self):
        result = count_todos_and_fixmes(SIMPLE_CODE)
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# Tests : check_documentation_ratio
# ---------------------------------------------------------------------------

class TestCheckDocumentationRatio:
    def test_partial_documentation(self):
        result = check_documentation_ratio(DOCUMENTED_CODE)
        assert result["total_functions"] == 3
        assert result["documented_functions"] == 2
        assert abs(result["documentation_ratio_percent"] - 66.7) < 1.0

    def test_no_functions(self):
        result = check_documentation_ratio("x = 1")
        assert result["total_functions"] == 0
        assert result["documentation_ratio"] is None

    def test_invalid_python_returns_error(self):
        result = check_documentation_ratio("def broken(:")
        assert "error" in result


# ---------------------------------------------------------------------------
# Tests : analyze_complexity
# ---------------------------------------------------------------------------

class TestAnalyzeComplexity:
    def test_simple_function_not_flagged(self):
        result = analyze_complexity(SIMPLE_CODE, threshold=5)
        assert "complex_functions" in result
        assert len(result["complex_functions"]) == 0

    def test_complex_function_detected(self):
        result = analyze_complexity(COMPLEX_CODE, threshold=5)
        assert len(result["complex_functions"]) >= 1
        assert result["complex_functions"][0]["name"] == "complex_func"

    def test_returns_error_on_invalid_python(self):
        result = analyze_complexity("def broken(:")
        # radon itself may raise SyntaxError or return empty, either is fine
        assert "error" in result or result.get("complex_functions") == []


# ---------------------------------------------------------------------------
# Tests : detect_code_duplication_simple
# ---------------------------------------------------------------------------

class TestDetectCodeDuplicationSimple:
    def test_identical_files(self):
        result = detect_code_duplication_simple(SIMPLE_CODE, SIMPLE_CODE)
        assert result["similarity_percent"] == 100.0

    def test_partial_duplication(self):
        result = detect_code_duplication_simple(DUPLICATE_A, DUPLICATE_B)
        assert result["similarity_percent"] > 0
        assert result["similarity_percent"] < 100

    def test_empty_file(self):
        result = detect_code_duplication_simple("", SIMPLE_CODE)
        assert result["similarity_percent"] == 0
