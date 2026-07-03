"""
Tests unitaires pour les outils de securite (osv_tools.py).
Teste : detection de secrets par regex et parsing de requirements.
Les tests OSV.dev font appel au reseau (marques avec @pytest.mark.network).
"""

import pytest
from unittest.mock import patch, MagicMock
from codesleuth.tools.osv_tools import (
    detect_potential_secrets,
    check_vulnerabilities,
    _parse_requirements,
)


# ---------------------------------------------------------------------------
# Tests : detect_potential_secrets
# ---------------------------------------------------------------------------

class TestDetectPotentialSecrets:
    def test_aws_key_detected(self):
        code = 'aws_access_key = "AKIAIOSFODNN7EXAMPLE"\n'
        result = detect_potential_secrets(code, "config.py")
        assert result["finding_count"] > 0
        assert any("AWS" in f["pattern"] for f in result["findings"])

    def test_github_token_detected(self):
        code = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"\n'
        result = detect_potential_secrets(code, "auth.py")
        assert result["finding_count"] > 0
        assert any("GitHub" in f["pattern"] for f in result["findings"])

    def test_private_key_header_detected(self):
        code = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n"
        result = detect_potential_secrets(code, "key.pem")
        assert result["finding_count"] > 0
        assert any("Private" in f["pattern"] for f in result["findings"])

    def test_clean_code_no_findings(self):
        code = """
def get_data(url: str) -> dict:
    \"\"\"Fetches data from URL.\"\"\"
    import httpx
    response = httpx.get(url)
    return response.json()
"""
        result = detect_potential_secrets(code, "utils.py")
        assert result["finding_count"] == 0
        assert result["findings"] == []

    def test_google_api_key_detected(self):
        code = 'api_key = "AIzaSyDexampleXYZ1234567890abcdefghijklmno"\n'
        result = detect_potential_secrets(code, "config.py")
        assert result["finding_count"] > 0

    def test_secret_value_masked_in_snippet(self):
        code = 'password = "supersecret123"\n'
        result = detect_potential_secrets(code, "settings.py")
        # If found, the actual value should be masked
        if result["finding_count"] > 0:
            for f in result["findings"]:
                assert "supersecret123" not in f["snippet"]

    def test_filepath_included_in_result(self):
        code = 'GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"\n'
        result = detect_potential_secrets(code, "my_module.py")
        assert result["filepath"] == "my_module.py"

    def test_lineno_correct(self):
        code = "x = 1\ny = 2\ntoken = 'ghp_abcdefghijklmnopqrstuvwxyz123456789012'\n"
        result = detect_potential_secrets(code, "test.py")
        if result["finding_count"] > 0:
            assert result["findings"][0]["lineno"] == 3


# ---------------------------------------------------------------------------
# Tests : _parse_requirements
# ---------------------------------------------------------------------------

class TestParseRequirements:
    def test_basic_requirements_txt(self):
        content = """
requests==2.28.0
flask>=3.0.0
numpy
# a comment line
-r other.txt
"""
        packages = _parse_requirements(content)
        names = [p[0] for p in packages]
        assert "requests" in names
        assert "flask" in names
        assert "numpy" in names
        # Comment and -r lines should be ignored
        assert len([p for p in packages if p[0].startswith("#")]) == 0

    def test_exact_version_captured(self):
        content = "django==4.2.0\n"
        packages = _parse_requirements(content)
        assert packages[0] == ("django", "4.2.0")

    def test_gte_version_returns_none_version(self):
        content = "flask>=3.0.0\n"
        packages = _parse_requirements(content)
        # >= version is not pinned — we pass None
        assert packages[0][0] == "flask"
        assert packages[0][1] is None

    def test_empty_content(self):
        assert _parse_requirements("") == []

    def test_extras_stripped(self):
        content = "requests[security]>=2.28\n"
        packages = _parse_requirements(content)
        assert packages[0][0] == "requests"


# ---------------------------------------------------------------------------
# Tests : check_vulnerabilities (mocked to avoid real network calls)
# ---------------------------------------------------------------------------

class TestCheckVulnerabilitiesMocked:
    def test_vuln_found(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-fake-0000",
                    "summary": "Test vulnerability",
                    "published": "2024-01-01T00:00:00Z",
                    "aliases": ["CVE-2024-0000"],
                    "severity": [{"type": "CVSS_V3", "score": "HIGH"}],
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response):
            result = check_vulnerabilities("requests", "PyPI", "2.0.0")

        assert result["package"] == "requests"
        assert result["vuln_count"] == 1
        assert result["vulnerabilities"][0]["id"] == "GHSA-fake-0000"

    def test_no_vulns(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulns": []}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response):
            result = check_vulnerabilities("safe-package", "PyPI")

        assert result["vuln_count"] == 0
        assert result["vulnerabilities"] == []

    def test_timeout_returns_error(self):
        import httpx as _httpx
        with patch("httpx.post", side_effect=_httpx.TimeoutException("timeout")):
            result = check_vulnerabilities("requests", "PyPI")
        assert "error" in result
        assert "Timeout" in result["error"]


# ---------------------------------------------------------------------------
# Network tests (require internet access — skip in CI if needed)
# ---------------------------------------------------------------------------

@pytest.mark.network
class TestCheckVulnerabilitiesNetwork:
    """These tests hit the real OSV.dev API. Skip with: pytest -m 'not network'"""

    def test_known_vulnerable_package(self):
        # An old version of urllib3 has known CVEs
        result = check_vulnerabilities("urllib3", "PyPI", "1.25.3")
        assert "vuln_count" in result
        assert result["package"] == "urllib3"
        # urllib3 1.25.3 has known CVEs
        assert result["vuln_count"] > 0

    def test_safe_package_no_vulns(self):
        # A fictional package that should return no vulns
        result = check_vulnerabilities("this-package-does-not-exist-xyz", "PyPI")
        assert result["vuln_count"] == 0
