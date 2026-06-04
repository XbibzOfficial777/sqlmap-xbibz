#!/usr/bin/env python

"""
Unit tests for lib.controller.auto module (Xbibz Official AutoEngine v3.0)
Tests critical functions for --auto and --spider mode integration.
"""

import sys
import os
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock the sqlmap dependencies before importing auto module
from lib.core.datatype import AttribDict
from lib.core.data import conf, kb


class TestClassifyParamPriority(unittest.TestCase):
    """Test _classifyParamPriority function for SQLi priority classification."""

    def setUp(self):
        from lib.controller.auto import _classifyParamPriority

    def test_high_priority_params(self):
        from lib.controller.auto import _classifyParamPriority
        high_params = ["id", "uid", "cat", "user", "sql", "db", "query", "search"]
        for param in high_params:
            result = _classifyParamPriority(param)
            self.assertEqual(result, "high", "Parameter '%s' should be HIGH priority, got %s" % (param, result))

    def test_medium_priority_params(self):
        from lib.controller.auto import _classifyParamPriority
        medium_params = ["name", "email", "date", "lang", "callback"]
        for param in medium_params:
            result = _classifyParamPriority(param)
            self.assertEqual(result, "medium", "Parameter '%s' should be MEDIUM priority, got %s" % (param, result))

    def test_low_priority_params(self):
        from lib.controller.auto import _classifyParamPriority
        low_params = ["style", "theme", "debug", "version", "session", "csrf"]
        for param in low_params:
            result = _classifyParamPriority(param)
            self.assertEqual(result, "low", "Parameter '%s' should be LOW priority, got %s" % (param, result))

    def test_unknown_params_default_low(self):
        from lib.controller.auto import _classifyParamPriority
        result = _classifyParamPriority("foobar_unknown_param")
        self.assertEqual(result, "low", "Unknown parameter should default to LOW priority")

    def test_partial_match_high(self):
        from lib.controller.auto import _classifyParamPriority
        result = _classifyParamPriority("user_id")
        self.assertEqual(result, "high", "Partial match 'user_id' containing 'user' should be HIGH")

    def test_case_insensitive(self):
        from lib.controller.auto import _classifyParamPriority
        result = _classifyParamPriority("ID")
        self.assertEqual(result, "high", "Case-insensitive match: 'ID' should be HIGH")


class TestCleanSpiderUrl(unittest.TestCase):
    """Test _cleanSpiderUrl for URL cleaning and deduplication."""

    def test_removes_port_80(self):
        from lib.controller.auto import _cleanSpiderUrl
        result = _cleanSpiderUrl("http://example.com:80/page?id=1")
        self.assertIsNotNone(result)
        self.assertNotIn(":80", result)

    def test_removes_port_443(self):
        from lib.controller.auto import _cleanSpiderUrl
        result = _cleanSpiderUrl("https://example.com:443/page?id=1")
        self.assertIsNotNone(result)
        self.assertNotIn(":443", result)

    def test_filters_static_extensions(self):
        from lib.controller.auto import _cleanSpiderUrl
        static_exts = [".jpg", ".css", ".js", ".png", ".pdf", ".gif"]
        for ext in static_exts:
            result = _cleanSpiderUrl("http://example.com/path/file%s" % ext)
            self.assertIsNone(result, "URL with extension %s should be filtered out" % ext)

    def test_replaces_params_with_placeholder(self):
        from lib.controller.auto import _cleanSpiderUrl
        result = _cleanSpiderUrl("http://example.com/page?id=1&name=test")
        self.assertIsNotNone(result)
        self.assertIn("FUZZ", result)
        self.assertNotIn("=1", result)
        self.assertNotIn("=test", result)

    def test_keeps_dynamic_urls(self):
        from lib.controller.auto import _cleanSpiderUrl
        result = _cleanSpiderUrl("http://example.com/page.php?id=1")
        self.assertIsNotNone(result)
        self.assertIn("?", result)


class TestExtractDomain(unittest.TestCase):
    """Test _extractDomain for domain extraction from URLs."""

    def test_simple_domain(self):
        from lib.controller.auto import _extractDomain
        result = _extractDomain("http://example.com/page")
        self.assertEqual(result, "example.com")

    def test_removes_www_prefix(self):
        from lib.controller.auto import _extractDomain
        result = _extractDomain("http://www.example.com/page")
        self.assertEqual(result, "example.com")

    def test_removes_port(self):
        from lib.controller.auto import _extractDomain
        result = _extractDomain("http://example.com:8080/page")
        self.assertEqual(result, "example.com")

    def test_invalid_url(self):
        from lib.controller.auto import _extractDomain
        result = _extractDomain("not-a-url")
        self.assertIsNone(result)


class TestFingerprintWaf(unittest.TestCase):
    """Test fingerprintWaf for WAF detection from response data."""

    def test_cloudflare_header_detection(self):
        from lib.controller.auto import fingerprintWaf
        headers = {"cf-ray": "some-value", "server": "cloudflare"}
        result = fingerprintWaf(responseHeaders=headers)
        self.assertIn("Cloudflare", result)
        self.assertGreater(result["Cloudflare"], 0)

    def test_empty_inputs(self):
        from lib.controller.auto import fingerprintWaf
        result = fingerprintWaf()
        self.assertEqual(result, {})

    def test_no_waf_detected(self):
        from lib.controller.auto import fingerprintWaf
        headers = {"content-type": "text/html", "server": "apache"}
        result = fingerprintWaf(responseHeaders=headers)
        self.assertEqual(result, {})

    def test_modsecurity_body_detection(self):
        from lib.controller.auto import fingerprintWaf
        body = '<html><body>mod_security has detected an attack</body></html>'
        result = fingerprintWaf(responseBody=body)
        self.assertIn("ModSecurity", result)

    def test_status_code_boost(self):
        from lib.controller.auto import fingerprintWaf
        headers = {"cf-ray": "some-value"}
        result_no_status = fingerprintWaf(responseHeaders=headers)
        result_with_status = fingerprintWaf(responseHeaders=headers, statusCode=403)
        # Status code boost should increase confidence
        if "Cloudflare" in result_no_status and "Cloudflare" in result_with_status:
            self.assertGreaterEqual(result_with_status["Cloudflare"], result_no_status["Cloudflare"])


class TestSortParamsBySqliPriority(unittest.TestCase):
    """Test _sortParamsBySqliPriority for URL priority sorting."""

    def test_high_priority_comes_first(self):
        from lib.controller.auto import _sortParamsBySqliPriority
        urls = [
            "http://example.com/page?style=FUZZ",
            "http://example.com/page?id=FUZZ",
            "http://example.com/page?name=FUZZ",
        ]
        result = _sortParamsBySqliPriority(urls)
        # id (high) should come before name (medium) and style (low)
        id_idx = next(i for i, u in enumerate(result) if "id=" in u)
        name_idx = next(i for i, u in enumerate(result) if "name=" in u)
        style_idx = next(i for i, u in enumerate(result) if "style=" in u)
        self.assertLess(id_idx, name_idx, "HIGH priority (id) should sort before MEDIUM (name)")
        self.assertLess(name_idx, style_idx, "MEDIUM priority (name) should sort before LOW (style)")


class TestSelectBypassStrategy(unittest.TestCase):
    """Test _selectBypassStrategy for WAF bypass strategy selection."""

    def test_cloudflare_strategy(self):
        from lib.controller.auto import _selectBypassStrategy
        result = _selectBypassStrategy(["Cloudflare"])
        self.assertIn("charencode", result["tampers"])
        self.assertIn("randomcase", result["tampers"])
        self.assertEqual(result["delay_ms"], 100)

    def test_generic_fallback(self):
        from lib.controller.auto import _selectBypassStrategy
        result = _selectBypassStrategy(["UnknownWAF"])
        self.assertIn("charencode", result["tampers"])

    def test_empty_waf_list(self):
        from lib.controller.auto import _selectBypassStrategy
        result = _selectBypassStrategy([])
        self.assertIn("charencode", result["tampers"])

    def test_multiple_wafs_merge(self):
        from lib.controller.auto import _selectBypassStrategy
        result = _selectBypassStrategy(["Cloudflare", "ModSecurity"])
        # Should merge tampers from both
        self.assertIn("charencode", result["tampers"])
        # ModSecurity-specific tamper
        self.assertIn("modsecurityversioned", result["tampers"])
        # Cloudflare-specific tamper
        self.assertIn("space2comment", result["tampers"])


class TestEscalationStages(unittest.TestCase):
    """Test progressive escalation stage configuration."""

    def test_six_stages_defined(self):
        from lib.controller.auto import ESCALATION_STAGES
        self.assertEqual(len(ESCALATION_STAGES), 6)

    def test_stages_are_progressive(self):
        from lib.controller.auto import ESCALATION_STAGES
        for i in range(1, len(ESCALATION_STAGES)):
            self.assertGreaterEqual(
                len(ESCALATION_STAGES[i]),
                len(ESCALATION_STAGES[i - 1]),
                "Stage %d should have >= tampers than stage %d" % (i, i - 1)
            )

    def test_first_stage_minimal(self):
        from lib.controller.auto import ESCALATION_STAGES
        self.assertEqual(len(ESCALATION_STAGES[0]), 1, "Stage 1 should have exactly 1 tamper")

    def test_last_stage_aggressive(self):
        from lib.controller.auto import ESCALATION_STAGES
        self.assertGreaterEqual(len(ESCALATION_STAGES[-1]), 6, "Final stage should have 6+ tampers")


class TestApplyTampers(unittest.TestCase):
    """Test _applyTampers for tamper script application."""

    def test_adds_new_tampers(self):
        from lib.controller.auto import _applyTampers
        conf.tamper = "space2comment"
        _applyTampers(["charencode", "randomcase"])
        self.assertIn("charencode", conf.tamper)
        self.assertIn("randomcase", conf.tamper)
        self.assertIn("space2comment", conf.tamper)
        conf.tamper = None  # cleanup

    def test_no_duplicate_tampers(self):
        from lib.controller.auto import _applyTampers
        conf.tamper = "charencode"
        _applyTampers(["charencode", "randomcase"])
        # Count occurrences of charencode in the tamper string
        tampers = conf.tamper.split(",")
        charencode_count = tampers.count("charencode")
        self.assertEqual(charencode_count, 1, "charencode should not be duplicated")
        conf.tamper = None  # cleanup

    def test_empty_tamper_list(self):
        from lib.controller.auto import _applyTampers
        conf.tamper = None
        _applyTampers([])
        # Should not crash with empty list
        conf.tamper = None  # cleanup


class TestWafFingerprintDatabase(unittest.TestCase):
    """Test WAF fingerprint database integrity."""

    def test_all_wafs_have_fingerprints(self):
        from lib.controller.auto import WAF_FINGERPRINT_HEADERS
        for waf_name, fingerprint in WAF_FINGERPRINT_HEADERS.items():
            self.assertIn("headers", fingerprint, "WAF '%s' missing 'headers'" % waf_name)
            self.assertIn("body_patterns", fingerprint, "WAF '%s' missing 'body_patterns'" % waf_name)
            self.assertIn("confidence", fingerprint, "WAF '%s' missing 'confidence'" % waf_name)
            self.assertGreater(fingerprint["confidence"], 0, "WAF '%s' confidence must be > 0" % waf_name)
            self.assertLessEqual(fingerprint["confidence"], 1.0, "WAF '%s' confidence must be <= 1.0" % waf_name)

    def test_all_wafs_have_bypass_strategies(self):
        from lib.controller.auto import WAF_FINGERPRINT_HEADERS, WAF_BYPASS_STRATEGIES
        for waf_name in WAF_FINGERPRINT_HEADERS:
            if waf_name in WAF_BYPASS_STRATEGIES:
                strategy = WAF_BYPASS_STRATEGIES[waf_name]
                self.assertIn("tampers", strategy, "Strategy for '%s' missing 'tampers'" % waf_name)
                self.assertIn("delay_ms", strategy, "Strategy for '%s' missing 'delay_ms'" % waf_name)
                self.assertGreaterEqual(len(strategy["tampers"]), 1, "Strategy for '%s' should have >= 1 tamper" % waf_name)


class TestDomParamPatterns(unittest.TestCase):
    """Test DOM parameter mining patterns."""

    def test_form_input_pattern(self):
        from lib.controller.auto import _mineDomParams
        html = '<input type="text" name="username" value="">'
        result = _mineDomParams(html)
        self.assertIn("username", result)

    def test_anchor_href_pattern(self):
        from lib.controller.auto import _mineDomParams
        html = '<a href="/page?id=123">link</a>'
        result = _mineDomParams(html)
        self.assertIn("id", result)

    def test_empty_content(self):
        from lib.controller.auto import _mineDomParams
        result = _mineDomParams("")
        self.assertEqual(result, set())

    def test_none_content(self):
        from lib.controller.auto import _mineDomParams
        result = _mineDomParams(None)
        self.assertEqual(result, set())


if __name__ == "__main__":
    unittest.main()
