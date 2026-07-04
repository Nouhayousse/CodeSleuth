# -*- coding: utf-8 -*-
"""
Tests for compute_hotspot_score in codesleuth/tools/code_analysis.py
"""
import pytest
from codesleuth.tools.code_analysis import compute_hotspot_score


class TestComputeHotspotScore:

    def test_zero_commits_is_stable(self):
        result = compute_hotspot_score(complexity_score=20, commit_count=0)
        assert result["hotspot_score"] == 0
        assert result["risk_level"] == "STABLE"

    def test_zero_complexity_is_stable(self):
        result = compute_hotspot_score(complexity_score=0, commit_count=50)
        assert result["hotspot_score"] == 0
        assert result["risk_level"] == "STABLE"

    def test_moderate_hotspot_boundary_above(self):
        # score = 5 * 9 = 45 → MODERATE HOTSPOT
        result = compute_hotspot_score(complexity_score=5, commit_count=9)
        assert result["hotspot_score"] == 45
        assert result["risk_level"] == "MODERATE HOTSPOT"

    def test_moderate_hotspot_boundary_below(self):
        # score = 5 * 8 = 40 → STABLE (border)
        result = compute_hotspot_score(complexity_score=5, commit_count=8)
        assert result["hotspot_score"] == 40
        assert result["risk_level"] == "STABLE"

    def test_critical_hotspot_boundary_above(self):
        # score = 10 * 11 = 110 → CRITICAL HOTSPOT
        result = compute_hotspot_score(complexity_score=10, commit_count=11)
        assert result["hotspot_score"] == 110
        assert result["risk_level"] == "CRITICAL HOTSPOT"

    def test_critical_hotspot_boundary_exact(self):
        # score = 101 → CRITICAL HOTSPOT
        result = compute_hotspot_score(complexity_score=101, commit_count=1)
        assert result["hotspot_score"] == 101
        assert result["risk_level"] == "CRITICAL HOTSPOT"

    def test_result_contains_all_keys(self):
        result = compute_hotspot_score(complexity_score=8, commit_count=15)
        for key in ("hotspot_score", "risk_level", "complexity_component", "churn_component"):
            assert key in result

    def test_components_are_preserved(self):
        result = compute_hotspot_score(complexity_score=7, commit_count=12)
        assert result["complexity_component"] == 7
        assert result["churn_component"] == 12
        assert result["hotspot_score"] == 7 * 12

    def test_typical_complex_file_high_churn(self):
        """Simulates a real hotspot: complexity=15, commits=20 in 90 days → score=300."""
        result = compute_hotspot_score(complexity_score=15, commit_count=20)
        assert result["hotspot_score"] == 300
        assert result["risk_level"] == "CRITICAL HOTSPOT"

    def test_typical_stable_legacy_file(self):
        """Complex file never modified: complexity=18, commits=0 → score=0."""
        result = compute_hotspot_score(complexity_score=18, commit_count=0)
        assert result["hotspot_score"] == 0
        assert result["risk_level"] == "STABLE"
