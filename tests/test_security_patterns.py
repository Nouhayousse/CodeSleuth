# -*- coding: utf-8 -*-
"""
Tests for codesleuth/tools/security_patterns.py
Covers all 5 features of the Senior Security Reviewer Agent.
"""

import pytest
from codesleuth.tools.security_patterns import (
    scan_dangerous_patterns,
    analyze_attack_surface,
    detect_security_smells,
    map_to_owasp,
    compute_security_score,
)


# ===========================================================================
# FEATURE 1 — scan_dangerous_patterns
# ===========================================================================


class TestScanDangerousPatternsPython:

    def test_eval_detected(self):
        code = "result = eval(user_input)"
        findings = scan_dangerous_patterns("app.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-001" in ids

    def test_exec_detected(self):
        code = "exec(open('script.py').read())"
        findings = scan_dangerous_patterns("main.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-002" in ids

    def test_subprocess_shell_true_detected(self):
        code = "subprocess.run(cmd, shell=True)"
        findings = scan_dangerous_patterns("runner.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-003" in ids

    def test_subprocess_shell_false_not_detected(self):
        code = "subprocess.run(['ls', '-la'], shell=False)"
        findings = scan_dangerous_patterns("runner.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-003" not in ids

    def test_pickle_loads_detected(self):
        code = "data = pickle.loads(raw_bytes)"
        findings = scan_dangerous_patterns("serializer.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-004" in ids

    def test_yaml_load_without_safeloader_detected(self):
        code = "config = yaml.load(stream)"
        findings = scan_dangerous_patterns("config.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-005" in ids

    def test_hashlib_md5_detected(self):
        code = "digest = hashlib.md5(data).hexdigest()"
        findings = scan_dangerous_patterns("hash_util.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-006" in ids

    def test_hashlib_sha1_detected(self):
        code = "h = hashlib.sha1(content)"
        findings = scan_dangerous_patterns("util.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-007" in ids

    def test_os_system_detected(self):
        code = "os.system('rm -rf /tmp/old')"
        findings = scan_dangerous_patterns("cleaner.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-008" in ids

    def test_tempfile_mktemp_detected(self):
        code = "tmpname = tempfile.mktemp(suffix='.dat')"
        findings = scan_dangerous_patterns("tmp.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-009" in ids

    def test_dunder_import_detected(self):
        code = "mod = __import__(module_name)"
        findings = scan_dangerous_patterns("loader.py", code)
        ids = [f["id"] for f in findings]
        assert "PY-010" in ids

    def test_severity_is_critical_for_eval(self):
        code = "eval(x)"
        findings = scan_dangerous_patterns("a.py", code)
        eval_finding = next((f for f in findings if f["id"] == "PY-001"), None)
        assert eval_finding is not None
        assert eval_finding["severity"] == "Critical"

    def test_no_false_positive_on_clean_code(self):
        code = """\
import hashlib
import json

def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def parse(text: str) -> dict:
    return json.loads(text)
"""
        findings = scan_dangerous_patterns("clean.py", code)
        assert findings == []

    def test_owasp_field_present(self):
        code = "eval(x)"
        findings = scan_dangerous_patterns("a.py", code)
        assert all("owasp" in f for f in findings)

    def test_snippet_is_truncated_to_160(self):
        long_line = "eval(" + "x" * 200 + ")"
        findings = scan_dangerous_patterns("a.py", long_line)
        assert len(findings[0]["snippet"]) <= 160

    def test_java_patterns_ignored_for_py_files(self):
        """Java patterns should NOT fire on .py files."""
        code = "Runtime.getRuntime().exec(cmd)"
        findings = scan_dangerous_patterns("utils.py", code)
        ids = [f["id"] for f in findings]
        assert "JV-001" not in ids


class TestScanDangerousPatternsJava:

    def test_runtime_exec_detected(self):
        code = "Process p = Runtime.getRuntime().exec(cmd);"
        findings = scan_dangerous_patterns("Executor.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-001" in ids

    def test_processbuilder_detected(self):
        code = "ProcessBuilder pb = new ProcessBuilder(args);"
        findings = scan_dangerous_patterns("Runner.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-002" in ids

    def test_statement_sql_detected(self):
        code = 'stmt.executeQuery("SELECT * FROM users WHERE id=" + id);'
        findings = scan_dangerous_patterns("UserRepo.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-003" in ids

    def test_object_input_stream_detected(self):
        code = "ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());"
        findings = scan_dangerous_patterns("Deserializer.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-004" in ids

    def test_class_for_name_detected(self):
        code = "Class<?> clazz = Class.forName(userInput);"
        findings = scan_dangerous_patterns("Plugin.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-005" in ids

    def test_set_accessible_detected(self):
        code = "field.setAccessible(true);"
        findings = scan_dangerous_patterns("Reflection.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-006" in ids

    def test_md5_java_detected(self):
        code = 'MessageDigest md = MessageDigest.getInstance("MD5");'
        findings = scan_dangerous_patterns("HashUtil.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-007" in ids

    def test_sha1_java_detected(self):
        code = 'MessageDigest sha = MessageDigest.getInstance("SHA-1");'
        findings = scan_dangerous_patterns("Hash.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-008" in ids

    def test_des_algo_detected(self):
        code = 'Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");'
        findings = scan_dangerous_patterns("Crypto.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-009" in ids

    def test_csrf_disable_detected(self):
        code = "http.csrf().disable();"
        findings = scan_dangerous_patterns("SecurityConfig.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-010" in ids

    def test_new_random_detected(self):
        code = "Random rng = new Random();"
        findings = scan_dangerous_patterns("Token.java", code)
        ids = [f["id"] for f in findings]
        assert "JV-011" in ids

    def test_python_patterns_ignored_for_java_files(self):
        """Python patterns should NOT fire on .java files."""
        code = "eval(x)"
        findings = scan_dangerous_patterns("Utils.java", code)
        ids = [f["id"] for f in findings]
        assert "PY-001" not in ids

    def test_finding_structure_complete(self):
        code = "Runtime.getRuntime().exec(cmd);"
        findings = scan_dangerous_patterns("Exec.java", code)
        f = findings[0]
        for key in ("id", "file", "line", "severity", "title", "risk", "remediation", "owasp", "snippet"):
            assert key in f, f"Missing key: {key}"


# ===========================================================================
# FEATURE 2 — analyze_attack_surface
# ===========================================================================


class TestAnalyzeAttackSurface:

    def _make_file(self, path: str, content: str) -> dict:
        return {"path": path, "content": content}

    def test_flask_route_detected(self):
        fl = [self._make_file("app.py", "@app.route('/api/users')\ndef users(): pass")]
        result = analyze_attack_surface(fl)
        assert result["counts"]["rest_endpoints"] >= 1

    def test_spring_controller_detected(self):
        fl = [self._make_file("Controller.java", "@RestController\npublic class UserController {}")]
        result = analyze_attack_surface(fl)
        assert result["counts"]["controllers"] >= 1

    def test_file_upload_detected(self):
        fl = [self._make_file("upload.py", "file = request.files['upload']\nfile.save('/tmp/f')")]
        result = analyze_attack_surface(fl)
        assert result["counts"]["file_uploads"] >= 1

    def test_db_access_detected(self):
        fl = [self._make_file("db.py", "cursor.execute('SELECT * FROM t')")]
        result = analyze_attack_surface(fl)
        assert result["counts"]["db_access"] >= 1

    def test_empty_repo_gives_low_rating(self):
        result = analyze_attack_surface([])
        assert result["rating"] == "LOW"

    def test_high_rating_many_endpoints(self):
        files = [
            self._make_file(f"route{i}.py", "@app.route('/ep')\ndef ep(): pass")
            for i in range(12)
        ]
        result = analyze_attack_surface(files)
        assert result["rating"] == "HIGH"

    def test_result_structure(self):
        result = analyze_attack_surface([])
        for key in ("counts", "files_by_category", "rating", "explanation", "total_surface_indicators"):
            assert key in result


# ===========================================================================
# FEATURE 3 — detect_security_smells
# ===========================================================================


class TestDetectSecuritySmells:

    def _make_file(self, path: str, content: str) -> dict:
        return {"path": path, "content": content}

    def test_dynamic_sql_smell_detected(self):
        code = 'query = "SELECT * FROM users WHERE id=" + user_id'
        result = detect_security_smells(
            file_list=[self._make_file("repo.py", code)],
            dangerous_findings=[],
            attack_surface={"counts": {}, "rating": "LOW"},
        )
        titles = [s["title"] for s in result]
        assert any("SQL" in t for t in titles)

    def test_permit_all_smell_detected(self):
        code = ".permitAll()"
        result = detect_security_smells(
            file_list=[self._make_file("SecurityConfig.java", code)],
            dangerous_findings=[],
            attack_surface={"counts": {}, "rating": "LOW"},
        )
        titles = [s["title"] for s in result]
        assert any("security" in t.lower() or "control" in t.lower() for t in titles)

    def test_god_security_object_smell(self):
        big_content = "\n".join(["x = 1"] * 600)  # 600 lines
        result = detect_security_smells(
            file_list=[self._make_file("auth_service.py", big_content)],
            dangerous_findings=[],
            attack_surface={"counts": {}, "rating": "LOW"},
        )
        titles = [s["title"] for s in result]
        assert any("God" in t for t in titles)

    def test_weak_crypto_concentration_smell(self):
        findings = [
            {"id": "PY-006", "owasp": "A02:Cryptographic Failures", "severity": "Medium",
             "file": "f0.py", "line": 1, "title": "MD5", "risk": "", "remediation": "", "snippet": ""},
            {"id": "PY-007", "owasp": "A02:Cryptographic Failures", "severity": "Medium",
             "file": "g.py", "line": 1, "title": "SHA1", "risk": "", "remediation": "", "snippet": ""},
            {"id": "JV-007", "owasp": "A02:Cryptographic Failures", "severity": "Medium",
             "file": "h.java", "line": 1, "title": "MD5", "risk": "", "remediation": "", "snippet": ""},
        ]
        result = detect_security_smells(
            file_list=[],
            dangerous_findings=findings,
            attack_surface={"counts": {}, "rating": "LOW"},
        )
        titles = [s["title"] for s in result]
        assert any("crypto" in t.lower() or "Crypto" in t for t in titles)

    def test_smell_structure(self):
        result = detect_security_smells([], [], {"counts": {}, "rating": "LOW"})
        for s in result:
            for key in ("severity", "title", "detail"):
                assert key in s


# ===========================================================================
# FEATURE 4 — map_to_owasp
# ===========================================================================


class TestMapToOwasp:

    def test_injection_finding_mapped(self):
        findings = [{
            "id": "PY-001", "owasp": "A03:Injection",
            "file": "a.py", "line": 1, "severity": "Critical",
            "title": "eval()", "risk": "", "remediation": "", "snippet": "",
        }]
        result = map_to_owasp(findings, cve_count=0, secret_count=0, smells=[])
        a03 = result["A03:Injection"]
        assert a03["findings"]
        assert "Detected" in [f["type"] for f in a03["findings"]]

    def test_cve_maps_to_a06(self):
        result = map_to_owasp([], cve_count=3, secret_count=0, smells=[])
        a06 = result["A06:Vulnerable Components"]
        assert any("CVE" in f["source"] or "3" in f["source"] for f in a06["findings"])

    def test_secrets_maps_to_a02(self):
        result = map_to_owasp([], cve_count=0, secret_count=2, smells=[])
        a02 = result["A02:Cryptographic Failures"]
        assert any(f["type"] == "Suspicious" for f in a02["findings"])

    def test_all_10_categories_present(self):
        result = map_to_owasp([], cve_count=0, secret_count=0, smells=[])
        expected = [f"A0{i}" for i in range(1, 10)] + ["A10"]
        for key in result:
            prefix = key.split(":")[0]
            assert prefix in [k.split(":")[0] for k in result]
        assert len(result) == 10

    def test_status_text_set(self):
        result = map_to_owasp([], cve_count=0, secret_count=0, smells=[])
        for cat_id, cat_data in result.items():
            assert "status" in cat_data and cat_data["status"]


# ===========================================================================
# FEATURE 5 — compute_security_score
# ===========================================================================


class TestComputeSecurityScore:

    def _empty_surface(self):
        return {"rating": "LOW", "counts": {}}

    def test_perfect_score_on_clean_repo(self):
        result = compute_security_score(
            cve_count=0, cve_critical=0, secret_count=0,
            dangerous_findings=[], smells=[],
            attack_surface=self._empty_surface(),
        )
        assert result["score"] == 30
        assert result["risk"] == "LOW"

    def test_critical_cve_deducts_points(self):
        result = compute_security_score(
            cve_count=2, cve_critical=2, secret_count=0,
            dangerous_findings=[], smells=[],
            attack_surface=self._empty_surface(),
        )
        assert result["score"] < 30
        assert any("CVE" in f and "Critical" in f for f in result["negative_factors"])

    def test_secrets_deduct_points(self):
        result = compute_security_score(
            cve_count=0, cve_critical=0, secret_count=3,
            dangerous_findings=[], smells=[],
            attack_surface=self._empty_surface(),
        )
        assert result["score"] < 30

    def test_critical_patterns_deduct_points(self):
        findings = [
            {"severity": "Critical", "owasp": "A03:Injection",
             "id": "PY-001", "file": "a.py", "line": 1,
             "title": "eval()", "risk": "", "remediation": "", "snippet": ""},
            {"severity": "Critical", "owasp": "A03:Injection",
             "id": "PY-002", "file": "a.py", "line": 2,
             "title": "exec()", "risk": "", "remediation": "", "snippet": ""},
        ]
        result = compute_security_score(
            cve_count=0, cve_critical=0, secret_count=0,
            dangerous_findings=findings, smells=[],
            attack_surface=self._empty_surface(),
        )
        assert result["score"] < 30
        assert any("API" in f and "critical" in f.lower() for f in result["negative_factors"])

    def test_score_never_negative(self):
        findings = [{"severity": "Critical", "owasp": "A03:Injection",
                     "id": f"X-{i:03d}", "file": "a.py", "line": i,
                     "title": "x", "risk": "", "remediation": "", "snippet": ""}
                    for i in range(20)]
        smells = [{"severity": "High", "title": f"Smell {i}", "detail": "", "file": None}
                  for i in range(10)]
        result = compute_security_score(
            cve_count=10, cve_critical=10, secret_count=5,
            dangerous_findings=findings, smells=smells,
            attack_surface={"rating": "HIGH", "counts": {}},
        )
        assert result["score"] >= 0

    def test_score_never_above_30(self):
        result = compute_security_score(
            cve_count=0, cve_critical=0, secret_count=0,
            dangerous_findings=[], smells=[],
            attack_surface=self._empty_surface(),
            has_active_maintenance=True, has_tests=True,
        )
        assert result["score"] <= 30

    def test_risk_levels(self):
        r = compute_security_score(0, 0, 0, [], [], self._empty_surface())
        assert r["risk"] == "LOW"

        findings = [{"severity": "Critical", "owasp": "A03:Injection",
                     "id": f"X-{i:03d}", "file": "a.py", "line": i,
                     "title": "x", "risk": "", "remediation": "", "snippet": ""}
                    for i in range(5)]
        r2 = compute_security_score(0, 0, 0, findings, [], self._empty_surface())
        assert r2["risk"] in ("HIGH", "CRITICAL", "MEDIUM")

    def test_result_structure(self):
        result = compute_security_score(0, 0, 0, [], [], self._empty_surface())
        for key in ("score", "max_score", "risk", "positive_factors", "negative_factors", "explanation"):
            assert key in result
        assert result["max_score"] == 30

    def test_tests_bonus_present(self):
        result = compute_security_score(
            cve_count=0, cve_critical=0, secret_count=0,
            dangerous_findings=[], smells=[],
            attack_surface=self._empty_surface(),
            has_tests=True,
        )
        assert any("tests" in f.lower() for f in result["positive_factors"])

    def test_high_attack_surface_deducts(self):
        surface = {"rating": "HIGH", "counts": {"rest_endpoints": 15}}
        result = compute_security_score(0, 0, 0, [], [], surface)
        assert any("surface" in f.lower() for f in result["negative_factors"])
