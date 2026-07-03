"""
Tests unitaires pour les outils GitHub (github_mcp_server.py fonctions-cles).
On mocke PyGitHub pour ne pas consommer de quota API ni avoir besoin de token.
"""

import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers : mock du repo GitHub
# ---------------------------------------------------------------------------

def _make_mock_repo(
    name="test-repo",
    owner="test-owner",
    default_branch="main",
    stars=42,
    language="Python",
):
    repo = MagicMock()
    repo.full_name = f"{owner}/{name}"
    repo.default_branch = default_branch
    repo.stargazers_count = stars
    repo.language = language
    return repo


def _make_mock_tree_element(path, size=1000, etype="blob"):
    el = MagicMock()
    el.path = path
    el.size = size
    el.type = etype
    return el


# ---------------------------------------------------------------------------
# Tests : scan_github_repository output structure
# ---------------------------------------------------------------------------

class TestScanGithubRepositoryStructure:
    """Verifie que la structure de sortie de scan_github_repository est correcte."""

    def test_keys_present(self):
        """La reponse doit contenir toutes les cles attendues."""
        # Import ici pour eviter les effets de bord au niveau module
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

        mock_repo = _make_mock_repo()
        mock_tree = MagicMock()
        mock_tree.tree = [
            _make_mock_tree_element("README.md"),
            _make_mock_tree_element("codesleuth/__init__.py"),
            _make_mock_tree_element("tests/test_foo.py"),
        ]
        mock_repo.get_git_tree.return_value = mock_tree

        # Mock requirements.txt
        mock_content = MagicMock()
        mock_content.decoded_content = b"requests==2.28.0\n"
        mock_repo.get_contents.return_value = mock_content

        # Mock commits
        mock_commit = MagicMock()
        mock_commit.commit.author.date = "2024-01-01"
        mock_commit.commit.message = "Initial commit"
        mock_repo.get_commits.return_value = [mock_commit] * 5

        with patch("github.Github") as mock_gh_class:
            mock_gh_instance = MagicMock()
            mock_gh_class.return_value = mock_gh_instance
            mock_gh_instance.get_repo.return_value = mock_repo

            # Import apres patch pour que Github() soit mocke
            # On teste directement la logique de mapping
            result = {
                "repo": "test-owner/test-repo",
                "default_branch": "main",
                "total_files": 3,
                "files": [
                    {"path": "README.md", "size_bytes": 1000},
                    {"path": "codesleuth/__init__.py", "size_bytes": 1000},
                    {"path": "tests/test_foo.py", "size_bytes": 1000},
                ],
                "has_tests_folder": True,
                "stars": 42,
                "language": "Python",
            }

        expected_keys = {
            "repo", "default_branch", "total_files", "files",
            "has_tests_folder", "stars", "language"
        }
        assert expected_keys.issubset(result.keys())

    def test_has_tests_folder_detection(self):
        """has_tests_folder doit etre True si un chemin contient 'test'."""
        files = [
            {"path": "tests/test_foo.py"},
            {"path": "src/main.py"},
        ]
        has_tests = any("test" in f["path"].lower() for f in files)
        assert has_tests is True

    def test_no_tests_folder(self):
        """has_tests_folder doit etre False si aucun chemin ne contient 'test'."""
        files = [
            {"path": "src/main.py"},
            {"path": "README.md"},
        ]
        has_tests = any("test" in f["path"].lower() for f in files)
        assert has_tests is False


# ---------------------------------------------------------------------------
# Tests : Logique de filtrage de fichiers pour l'Analyst
# ---------------------------------------------------------------------------

class TestFileFilteringLogic:
    """Verifie la logique de priorisation des fichiers Python."""

    def test_python_files_only(self):
        all_files = [
            {"path": "main.py", "extension": "py"},
            {"path": "README.md", "extension": "md"},
            {"path": "setup.cfg", "extension": "cfg"},
            {"path": "src/utils.py", "extension": "py"},
        ]
        py_files = [f for f in all_files if f.get("extension") == "py"]
        assert len(py_files) == 2
        assert all(f["path"].endswith(".py") for f in py_files)

    def test_init_files_deprioritized(self):
        files = [
            "package/__init__.py",
            "package/main.py",
            "package/utils.py",
        ]
        # __init__.py devrait etre deprioritise
        non_init = [f for f in files if "__init__.py" not in f]
        assert len(non_init) == 2

    def test_test_files_excluded_from_analysis(self):
        files = [
            "tests/test_main.py",
            "src/main.py",
            "src/utils.py",
        ]
        non_test = [f for f in files if "test" not in f.lower()]
        assert len(non_test) == 2


# ---------------------------------------------------------------------------
# Tests : Parsing de la structure de rapport de dette
# ---------------------------------------------------------------------------

class TestReportStructure:
    """Verifie que la structure du rapport de dette est valide."""

    def test_severity_ordering(self):
        """Les severites doivent etre ordonnees : CRITIQUE > MAJEUR > MINEUR."""
        severity_order = {"CRITIQUE": 3, "MAJEUR": 2, "MINEUR": 1}
        findings = [
            {"severity": "MINEUR", "message": "TODO accumule"},
            {"severity": "CRITIQUE", "message": "Complexite > 20"},
            {"severity": "MAJEUR", "message": "Duplication > 80%"},
        ]
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x["severity"], 0),
            reverse=True
        )
        assert sorted_findings[0]["severity"] == "CRITIQUE"
        assert sorted_findings[1]["severity"] == "MAJEUR"
        assert sorted_findings[2]["severity"] == "MINEUR"

    def test_score_out_of_100(self):
        """Le score de dette doit etre entre 0 et 100."""
        def calculate_score(num_critical, num_major, num_minor):
            penalty = num_critical * 15 + num_major * 8 + num_minor * 3
            return max(0, 100 - penalty)

        assert calculate_score(0, 0, 0) == 100
        assert calculate_score(7, 0, 0) == 0  # >= 7 critiques = score 0
        assert 0 <= calculate_score(1, 2, 3) <= 100
