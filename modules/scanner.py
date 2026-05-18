import concurrent.futures
import datetime
import hashlib
import html
import os
import random
import re
import socket
import ssl
import string
from dataclasses import dataclass, field
from typing import Optional
from difflib import SequenceMatcher
from urllib.parse import urlparse

import nmap
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .cvss_calculator import calculate_cvss_31, explain_cvss_31, cvss_vector
from .vulnerability_db import get_vuln_entry, get_header_entry, get_ssl_entry, get_port_entry

REQUEST_TIMEOUT = 7
MAX_BODY_ANALYSIS = 250_000

SEVERITY_ORDER = {
    "False Positive": 0,
    "Informational": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}


def sanitize(value):
    return html.escape(str(value or ""), quote=True)


def normalize_hostname(target_url):
    parsed = urlparse(target_url)
    hostname = parsed.netloc or parsed.path
    hostname = hostname.split("@").pop().split(":")[0]
    return hostname.strip("/")


def response_hash(text):
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def similarity_ratio(a, b):
    a = (a or "")[:MAX_BODY_ANALYSIS]
    b = (b or "")[:MAX_BODY_ANALYSIS]
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def extract_title(html_text):
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text or "", re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def severity_from_score(score):
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


def cvss_score(metrics):
    if not metrics:
        return 0.0
    return calculate_cvss_31(metrics)


@dataclass
class Evidence:
    finding_type: str
    target: str
    category: str = "public_files"
    status_code: int = 0
    final_url: str = ""
    redirect_count: int = 0
    content_type: str = ""
    content_length: int = 0
    title: str = ""
    similarity_to_404: float = 0.0
    is_similar_to_404: bool = False
    is_soft_404: bool = False
    is_spa_fallback: bool = False
    is_redirect_to_error: bool = False
    is_content_type_mismatch: bool = False
    sensitive_patterns_found: list = field(default_factory=list)
    service_name: str = ""
    service_product: str = ""
    service_version: str = ""
    port_number: int = 0
    protocol: str = "tcp"
    header_name: str = ""
    ssl_protocol: str = ""
    ssl_days_remaining: Optional[int] = None

    @property
    def confirmed_sensitive_exposure(self):
        # Critical exposure hanya berlaku untuk file/path sensitif.
        # Halaman login/admin normal tidak boleh menjadi Critical hanya karena ada teks seperti "api" di HTML.
        sensitive_categories = {"env_files", "git_files", "backup_files", "info_leak"}
        return (
            self.status_code == 200
            and self.category in sensitive_categories
            and bool(self.sensitive_patterns_found)
            and not self.is_similar_to_404
            and not self.is_soft_404
            and not self.is_spa_fallback
            and not self.is_content_type_mismatch
        )

    @property
    def is_false_positive(self):
        return any([
            self.is_redirect_to_error,
            self.is_soft_404,
            self.is_similar_to_404,
            self.is_spa_fallback,
            self.is_content_type_mismatch,
        ])


class DynamicScoringEngine:
    """Membangun CVSS, severity, dan confidence berdasarkan evidence aktual."""

    SENSITIVE_CATEGORIES = {"env_files", "git_files", "backup_files", "info_leak"}
    DATABASE_PORTS = {3306, 5432, 6379, 9200, 27017, 1521, 1433}
    REMOTE_ACCESS_PORTS = {21, 22, 23, 3389, 5900}
    SAFE_WEB_PORTS = {80, 443}

    def score_directory(self, ev: Evidence):
        kb = get_vuln_entry(ev.target)

        if ev.is_false_positive:
            return self._result(
                severity="False Positive",
                metrics=None,
                confidence=self._confidence(ev),
                reason=self._false_positive_reason(ev),
                solution="Tidak ada tindakan mendesak. Verifikasi manual hanya jika path dianggap sensitif.",
            )

        # Halaman login/admin yang hanya terdeteksi publik tidak boleh langsung dinilai Critical.
        # Login publik adalah kondisi normal pada portal, LMS, SIAKAD, e-learning, dan aplikasi berbasis autentikasi.
        auth_keywords = {"login", "admin", "administrator", "dashboard", "panel", "signin", "sign-in", "auth"}
        if ev.category == "admin_panels" or str(ev.target).lower().strip("/") in auth_keywords:
            return self._result(
                severity="Informational",
                metrics=None,
                confidence=self._confidence(ev),
                reason="Halaman login/admin terdeteksi dan dapat diakses publik. Ini merupakan perilaku normal pada sistem berbasis autentikasi, bukan bukti Broken Access Control atau kebocoran kredensial.",
                solution="Pastikan autentikasi kuat, HTTPS aktif, rate limiting diterapkan, MFA digunakan bila diperlukan, dan akses admin sensitif dibatasi.",
            )

        # Critical hanya diberikan jika data sensitif benar-benar muncul pada path sensitif,
        # bukan sekadar teks umum pada halaman login.
        if ev.confirmed_sensitive_exposure:
            metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
            return self._result(
                severity=severity_from_score(cvss_score(metrics)),
                metrics=metrics,
                confidence=self._confidence(ev),
                reason="Data sensitif terkonfirmasi muncul di respons HTTP.",
                solution=kb.get("solution"),
            )

        if ev.status_code == 200:
            if ev.category in self.SENSITIVE_CATEGORIES:
                metrics = {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}
                return self._result(
                    severity=severity_from_score(cvss_score(metrics)),
                    metrics=metrics,
                    confidence=self._confidence(ev),
                    reason="Path sensitif memberikan respons 200, tetapi tidak ditemukan pola credential/secret. Perlu verifikasi manual.",
                    solution=kb.get("solution"),
                )

            return self._result(
                severity="Informational",
                metrics=None,
                confidence=self._confidence(ev),
                reason="File/path publik ditemukan tanpa indikasi data sensitif.",
                solution=kb.get("solution"),
            )

        if ev.status_code == 403:
            metrics = {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}
            return self._result(
                severity=severity_from_score(cvss_score(metrics)),
                metrics=metrics,
                confidence=55,
                reason="Path terdeteksi tetapi akses ditolak (403). Ini menunjukkan proteksi aktif, bukan kebocoran langsung.",
                solution="Pertahankan aturan blokir dan pastikan file sensitif tidak berada di public web root.",
            )

        return self._result(
            severity="Informational",
            metrics=None,
            confidence=25,
            reason=f"Path tidak dapat diakses. Status HTTP: {ev.status_code}.",
            solution="Tidak ada tindakan mendesak.",
        )

    def score_port(self, ev: Evidence):
        port = int(ev.port_number or 0)
        kb = get_port_entry(port)
        service = (ev.service_name or "").lower()

        if port == 443:
            return self._result("Informational", None, 80, "HTTPS terbuka adalah kondisi normal untuk website publik.", kb.get("solution"))
        if port == 80:
            return self._result("Informational", None, 70, "HTTP terdeteksi. Risiko bergantung pada apakah trafik sensitif dipaksa ke HTTPS.", kb.get("solution"))
        if port == 22 and "tcpwrapped" in service:
            metrics = {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}
            return self._result(severity_from_score(cvss_score(metrics)), metrics, 45, "SSH terdeteksi tetapi service tampak dibatasi/firewalled (tcpwrapped).", kb.get("solution"))
        if port == 23:
            metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"}
            return self._result(severity_from_score(cvss_score(metrics)), metrics, 85, "Telnet terbuka dan menggunakan komunikasi plaintext.", kb.get("solution"))
        if port in self.DATABASE_PORTS:
            metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "L"}
            return self._result(severity_from_score(cvss_score(metrics)), metrics, 85, "Service database terbuka ke publik. Ini bukan selalu exploit, tetapi exposure-nya tinggi.", kb.get("solution"))
        if port in self.REMOTE_ACCESS_PORTS:
            metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"}
            return self._result(severity_from_score(cvss_score(metrics)), metrics, 70, "Service remote access terbuka dan menjadi attack surface.", kb.get("solution"))
        if port in {8080, 8443, 8000, 5000, 3000}:
            metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}
            return self._result(severity_from_score(cvss_score(metrics)), metrics, 65, "Port alternatif web/dev/admin terdeteksi. Risiko bergantung pada autentikasi dan akses publik.", kb.get("solution"))

        metrics = {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}
        return self._result(severity_from_score(cvss_score(metrics)), metrics, 45, "Port terbuka menambah attack surface, tetapi belum ada bukti vulnerability spesifik.", kb.get("solution"))

    def score_header(self, ev: Evidence):
        kb = get_header_entry(ev.header_name)
        name = ev.header_name.lower()

        # Static CVSS v3.1 metrics mapping for missing HTTP security headers.
        # Metrics are assigned based on the expected security impact of each missing header.
        header_metrics = {
            "strict-transport-security": {
                "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"
            },
            "content-security-policy": {
                "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"
            },
            "x-frame-options": {
                "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"
            },
            "x-content-type-options": {
                "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"
            },
            "referrer-policy": {
                "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"
            },
            "permissions-policy": {
                "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"
            },
        }

        metrics = header_metrics.get(name, {
            "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"
        })

        return self._result(severity_from_score(cvss_score(metrics)), metrics, 70, kb.get("danger"), kb.get("solution"))

    def score_ssl(self, ev: Evidence):
        if ev.ssl_days_remaining is not None and ev.ssl_days_remaining <= 0:
            metrics = {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}
            kb = get_ssl_entry("ssl_expired")
            return self._result(severity_from_score(cvss_score(metrics)), metrics, 90, kb.get("danger"), kb.get("solution"))
        if ev.ssl_days_remaining is not None and ev.ssl_days_remaining <= 14:
            metrics = {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"}
            kb = get_ssl_entry("ssl_expiring_soon")
            return self._result(severity_from_score(cvss_score(metrics)), metrics, 80, kb.get("danger"), kb.get("solution"))
        if ev.ssl_protocol in {"TLSv1", "TLSv1.1"}:
            metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"}
            kb = get_ssl_entry("weak_tls_protocol")
            return self._result(severity_from_score(cvss_score(metrics)), metrics, 80, kb.get("danger"), kb.get("solution"))
        return self._result("Informational", None, 80, "Konfigurasi SSL/TLS tampak valid dari pemeriksaan dasar.", "Pastikan tetap memperbarui sertifikat dan konfigurasi TLS.")

    def _confidence(self, ev: Evidence):
        score = 30
        if ev.status_code == 200:
            score += 15
        if ev.confirmed_sensitive_exposure:
            score += 45
        if ev.content_type and "text/html" not in ev.content_type:
            score += 8
        if ev.category in self.SENSITIVE_CATEGORIES:
            score += 8
        if ev.is_similar_to_404:
            score -= 35
        if ev.is_soft_404:
            score -= 30
        if ev.is_redirect_to_error:
            score -= 35
        if ev.is_spa_fallback:
            score -= 30
        if ev.is_content_type_mismatch:
            score -= 25
        return max(0, min(100, int(score)))

    def _false_positive_reason(self, ev: Evidence):
        reasons = []
        if ev.is_redirect_to_error:
            reasons.append("redirect ke halaman error/custom 404")
        if ev.is_soft_404:
            reasons.append("soft 404 terdeteksi")
        if ev.is_similar_to_404:
            reasons.append(f"mirip baseline 404 ({round(ev.similarity_to_404 * 100, 1)}%)")
        if ev.is_spa_fallback:
            reasons.append("SPA/catch-all routing")
        if ev.is_content_type_mismatch:
            reasons.append("Content-Type tidak sesuai")
        return "False positive karena " + ", ".join(reasons) + "."

    def _result(self, severity, metrics, confidence, reason, solution):
        # False Positive bukan vulnerability aktif, sehingga score dan metrics dibuat 0/None.
        score = 0.0 if severity == "False Positive" else cvss_score(metrics)
        return {
            "severity": severity,
            "score": score,
            "metrics": None if severity == "False Positive" else metrics,
            "confidence": int(confidence or 0),
            "reason": reason or "-",
            "solution": solution or "Tidak ada tindakan mendesak.",
        }


SCORING = DynamicScoringEngine()

class OwaspMapper:
    """Klasifikasi OWASP Top 10:2025 berbasis evidence hasil scan.

    OWASP digunakan sebagai kerangka klasifikasi, bukan sebagai kalkulator skor.
    Skor risiko tetap dihitung oleh CVSS v3.1, sedangkan class ini menentukan
    kategori OWASP yang paling relevan berdasarkan karakteristik evidence.
    """

    DATABASE_PORTS = {3306, 5432, 6379, 9200, 27017, 1521, 1433}
    REMOTE_ACCESS_PORTS = {21, 22, 23, 3389, 5900}
    DEV_ADMIN_PORTS = {3000, 5000, 8000, 8080, 8443}

    @staticmethod
    def classify(ev: Evidence):
        target = str(getattr(ev, "target", "") or "").lower()
        category = str(getattr(ev, "category", "") or "").lower()
        finding_type = str(getattr(ev, "finding_type", "") or "").lower()
        header_name = str(getattr(ev, "header_name", "") or "").lower()
        port_number = int(getattr(ev, "port_number", 0) or 0)
        ssl_protocol = str(getattr(ev, "ssl_protocol", "") or "")
        ssl_days = getattr(ev, "ssl_days_remaining", None)
        sensitive_hits = getattr(ev, "sensitive_patterns_found", []) or []

        if getattr(ev, "is_false_positive", False):
            return {
                "id": "N/A",
                "name": "Not Applicable",
                "reason": "Temuan ditandai sebagai false positive sehingga tidak dipetakan sebagai kerentanan OWASP aktif.",
            }

        if category == "admin_panels" or any(x in target for x in ["admin", "administrator", "dashboard", "login", "panel"]):
            return {
                "id": "N/A",
                "name": "Public Authentication Interface",
                "reason": "Halaman login/admin terdeteksi dapat diakses publik. Kondisi ini umum pada aplikasi web yang membutuhkan autentikasi pengguna dan belum membuktikan Broken Access Control.",
            }

        if finding_type == "header":
            return {
                "id": "A02:2025",
                "name": "Security Misconfiguration",
                "reason": f"Header keamanan {header_name or 'HTTP'} tidak ditemukan pada response utama.",
            }

        if category in {"env_files", "git_files", "backup_files", "info_leak"}:
            return {
                "id": "A02:2025",
                "name": "Security Misconfiguration",
                "reason": "File konfigurasi, backup, metadata, atau informasi teknis terekspos melalui web root.",
            }

        if sensitive_hits:
            return {
                "id": "A02:2025",
                "name": "Security Misconfiguration",
                "reason": "Response mengandung pola data sensitif seperti credential, token, API key, atau secret.",
            }

        if port_number in OwaspMapper.DATABASE_PORTS:
            return {
                "id": "A02:2025",
                "name": "Security Misconfiguration",
                "reason": "Port database/service internal terbuka ke jaringan publik.",
            }

        if port_number in OwaspMapper.REMOTE_ACCESS_PORTS or port_number in OwaspMapper.DEV_ADMIN_PORTS:
            return {
                "id": "A02:2025",
                "name": "Security Misconfiguration",
                "reason": "Service remote access, development, atau panel alternatif terdeteksi sebagai attack surface publik.",
            }

        if any(x in target for x in ["vendor", "node_modules", "composer.lock", "package-lock.json", "yarn.lock"]):
            return {
                "id": "A03:2025",
                "name": "Software Supply Chain Failures",
                "reason": "File dependency/package manager terdeteksi dan dapat membuka informasi rantai pasok perangkat lunak.",
            }

        if finding_type == "ssl" and ((ssl_days is not None and ssl_days <= 0) or ssl_protocol in {"TLSv1", "TLSv1.1"}):
            return {
                "id": "A04:2025",
                "name": "Cryptographic Failures",
                "reason": "Masalah SSL/TLS terdeteksi, seperti sertifikat kedaluwarsa atau protokol TLS lama.",
            }

        if any(x in target for x in ["sql", "query", "search", "id="]):
            return {
                "id": "A05:2025",
                "name": "Injection",
                "reason": "Parameter atau artefak yang berkaitan dengan query terdeteksi. Perlu pengujian khusus untuk konfirmasi injection.",
            }

        return {
            "id": "N/A",
            "name": "Informational / Uncategorized",
            "reason": "Temuan bersifat informasional atau belum memiliki bukti yang cukup untuk dipetakan ke kategori OWASP tertentu.",
        }


class SmartScanner:
    SOFT_404_KEYWORDS = ["404", "not found", "page not found", "halaman tidak ditemukan", "tidak ditemukan", "oops", "error page", "the page you are looking for"]
    SPA_INDICATORS = ['id="root"', "id='root'", 'id="app"', "id='app'", "react-root", "__next", "nuxt", "vite", "bundle.js", "app.js"]
    SENSITIVE_PATTERNS = {
        "API Key": r"(?i)\bAPI[_-]?KEY\s*[:=]\s*['\"]?[^'\"\s]{8,}",
        "DB Password": r"(?i)\bDB[_-]?PASSWORD\s*[:=]\s*['\"]?[^'\"\s]{4,}",
        "DB Username": r"(?i)\bDB[_-]?USERNAME\s*[:=]\s*['\"]?[^'\"\s]{2,}",
        "Secret Key": r"(?i)\b(SECRET[_-]?KEY|APP[_-]?KEY)\s*[:=]\s*['\"]?[^'\"\s]{8,}",
        "Private Key": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|(?i)\bPRIVATE[_-]?KEY\b",
        "AWS Access Key": r"(?i)\bAWS_ACCESS_KEY_ID\s*[:=]\s*['\"]?AKIA[0-9A-Z]{16}",
        "AWS Secret": r"(?i)\bAWS_SECRET_ACCESS_KEY\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}",
        "Token": r"(?i)\bTOKEN\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}",
        "Password": r"(?i)\bPASSWORD\s*[:=]\s*['\"]?[^'\"\s]{4,}",
    }
    FILE_CONTENT_TYPE_RULES = {
        ".env": ["text/plain", "application/octet-stream", "binary/octet-stream"],
        ".gitignore": ["text/plain", "application/octet-stream"],
        ".htaccess": ["text/plain", "application/octet-stream"],
        "web.config": ["text/xml", "application/xml", "text/plain", "application/octet-stream"],
        "config.json": ["application/json", "text/plain"],
        "robots.txt": ["text/plain"],
        "sitemap.xml": ["application/xml", "text/xml"],
    }

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "WebSecChecker-Scanner/3.0"})
        self.baseline_404 = self._get_baseline()

    def _fetch(self, url, allow_redirects=True):
        return self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)

    def _get_baseline(self):
        samples = []
        for _ in range(2):
            random_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
            try:
                samples.append(self._response_profile(self._fetch(f"{self.base_url}/{random_path}", True)))
            except requests.RequestException:
                pass
        return samples[0] if samples else None

    def _response_profile(self, res):
        text = (res.text or "")[:MAX_BODY_ANALYSIS]
        return {
            "status_code": res.status_code,
            "content_length": len(res.text or ""),
            "hash": response_hash(text),
            "final_url": res.url,
            "text": text.lower(),
            "raw_text": text,
            "content_type": res.headers.get("Content-Type", "").lower(),
            "title": extract_title(text).lower(),
            "headers": dict(res.headers),
            "redirect_count": len(res.history),
        }

    def _is_soft_404(self, profile):
        return any(k in profile["text"] or k in profile["title"] for k in self.SOFT_404_KEYWORDS)

    def _is_redirect_to_error(self, requested_url, profile):
        final_url = profile["final_url"].lower()
        if final_url == requested_url.lower():
            return False
        return any(marker in final_url for marker in ["404", "not-found", "not_found", "error", "check_404", "page-not-found"])

    def _similarity_to_baseline(self, profile):
        if not self.baseline_404:
            return False, 0.0
        if profile["hash"] == self.baseline_404["hash"]:
            return True, 1.0
        baseline_len = max(self.baseline_404["content_length"], 1)
        len_diff_ratio = abs(profile["content_length"] - baseline_len) / baseline_len
        sim = similarity_ratio(profile["raw_text"], self.baseline_404["raw_text"])
        similar = sim >= 0.90 or (sim >= 0.82 and len_diff_ratio <= 0.15) or (len_diff_ratio <= 0.03 and profile["title"] == self.baseline_404["title"])
        return similar, sim

    def _is_spa_catch_all(self, profile):
        if profile["status_code"] != 200:
            return False
        if not any(ind in profile["text"] for ind in self.SPA_INDICATORS):
            return False
        if self.baseline_404 and any(ind in self.baseline_404["text"] for ind in self.SPA_INDICATORS):
            similar, _ = self._similarity_to_baseline(profile)
            return similar
        return False

    def _content_type_mismatch(self, word_clean, profile):
        word = word_clean.lower().strip("/")
        content_type = profile["content_type"]
        raw_files = [".env", ".gitignore", ".htaccess", "web.config", "config.json"]
        if word in raw_files and "text/html" in content_type:
            return True
        allowed = self.FILE_CONTENT_TYPE_RULES.get(word)
        return bool(allowed and content_type and not any(a in content_type for a in allowed) and "text/html" in content_type)

    def _find_sensitive_patterns(self, text):
        hits = []
        for label, pattern in self.SENSITIVE_PATTERNS.items():
            if re.search(pattern, text or ""):
                hits.append(label)
        return hits

    def analyze_directory_path(self, full_path, word_clean):
        try:
            res = self._fetch(full_path, allow_redirects=True)
            profile = self._response_profile(res)
            kb = get_vuln_entry(word_clean)
            similar, sim_value = self._similarity_to_baseline(profile)
            ev = Evidence(
                finding_type="directory",
                target=word_clean,
                category=kb.get("category", "public_files"),
                status_code=profile["status_code"],
                final_url=profile["final_url"],
                redirect_count=profile["redirect_count"],
                content_type=profile["content_type"],
                content_length=profile["content_length"],
                title=profile["title"],
                similarity_to_404=sim_value,
                is_similar_to_404=similar,
                is_soft_404=self._is_soft_404(profile),
                is_spa_fallback=self._is_spa_catch_all(profile),
                is_redirect_to_error=self._is_redirect_to_error(full_path, profile),
                is_content_type_mismatch=self._content_type_mismatch(word_clean, profile),
                sensitive_patterns_found=[] if (
                    kb.get("category") == "admin_panels"
                    or word_clean.lower().strip("/") in {"login", "admin", "administrator", "dashboard", "panel", "signin", "sign-in", "auth"}
                ) else self._find_sensitive_patterns(profile["raw_text"]),
            )
            decision = SCORING.score_directory(ev)
            owasp = OwaspMapper.classify(ev)
            evidence = self._evidence_text(ev, decision, owasp)
            return self._format_output(kb.get("name", f"Path Analysis: {word_clean}"), word_clean, full_path, decision, evidence, owasp)
        except requests.RequestException as e:
            decision = {"severity": "Informational", "score": 0.0, "confidence": 0, "reason": f"Scan error: {str(e)}", "solution": "Coba scan ulang atau periksa koneksi target.", "metrics": None}
            owasp = {"id": "N/A", "name": "Scan Error", "reason": "Request gagal sehingga kategori OWASP tidak dapat ditentukan."}
            return self._format_output(f"Path Analysis: {word_clean}", word_clean, full_path, decision, "Request gagal", owasp)

    def _evidence_text(self, ev: Evidence, decision, owasp=None):
        parts = [
            f"Status: {ev.status_code}",
            f"Content-Type: {ev.content_type or '-'}",
            f"Similarity 404: {round(ev.similarity_to_404 * 100, 1)}%",
        ]
        if ev.sensitive_patterns_found:
            parts.append("Pola sensitif: " + ", ".join(ev.sensitive_patterns_found))
        else:
            parts.append("Pola sensitif: tidak ditemukan")
        if decision.get("metrics"):
            parts.append("CVSS Vector: " + "/".join(f"{k}:{v}" for k, v in decision["metrics"].items()))
        if owasp:
            parts.append("OWASP: " + str(owasp.get("id", "N/A")) + " - " + str(owasp.get("name", "-")))
        return " | ".join(parts)

    def _format_output(self, name, word, path, decision, evidence, owasp=None):
        category = decision["severity"]
        icons = {"Critical": "❌", "High": "❌", "Medium": "⚠️", "Low": "🟡", "Informational": "ℹ️", "False Positive": "✅"}
        colors = {"Critical": "#dc3545", "High": "#dc3545", "Medium": "#fd7e14", "Low": "#198754", "Informational": "#17a2b8", "False Positive": "#6c757d"}
        return {
            "badge_color": colors.get(category, "#6c757d"),
            "display_title": f"{icons.get(category, '')} {name}",
            "path": path,
            "score": float(decision.get("score") or 0.0),
            "severity": category,
            "danger": decision.get("reason", "-"),
            "solution": decision.get("solution", "Tidak ada tindakan mendesak."),
            "confidence": int(decision.get("confidence") or 0),
            "evidence": evidence,
            "metrics": decision.get("metrics"),
            "owasp": owasp or {"id": "N/A", "name": "Uncategorized", "reason": "Belum terpetakan ke kategori OWASP."},
        }



def create_cvss_detail_html(metrics):
    """Membuat blok detail matrix + perhitungan CVSS untuk UI dan PDF."""
    if not metrics:
        return ""

    detail = explain_cvss_31(metrics)
    rows = "".join(
        f"<tr><td><b>{sanitize(item['code'])}</b></td>"
        f"<td>{sanitize(item['name'])}</td>"
        f"<td>{sanitize(item['value'])} - {sanitize(item['label'])}</td>"
        f"<td>{'-' if item['numeric'] is None else format(item['numeric'], '.2f')}</td></tr>"
        for item in detail['matrix']
    )
    calc = "".join(f"<li>{sanitize(line)}</li>" for line in detail['calculation'])

    return f"""
    <details class="cvss-detail-box">
      <summary><b>Lihat detail matrix & perhitungan CVSS</b></summary>
      <div class="cvss-vector"><b>Vector:</b> {sanitize(detail['vector'])}</div>
      <table class="cvss-matrix-table">
        <thead><tr><th>Kode</th><th>Matrix</th><th>Nilai</th><th>Bobot</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <div class="cvss-formula-box">
        <b>Perhitungan:</b>
        <ol>{calc}</ol>
      </div>
    </details>"""

def create_card_html(badge_text, badge_color, title, body_content, score=None, severity=None, danger=None, solution=None, confidence=None, evidence=None, metrics=None, owasp=None):
    safe_title = sanitize(title)
    safe_body = str(body_content or "")
    safe_danger = sanitize(danger)
    safe_solution = sanitize(solution)
    safe_evidence = sanitize(evidence)

    score_badge = ""
    if score is not None and score > 0:
        color = "#dc3545" if score >= 7.0 else "#fd7e14" if score >= 4.0 else "#198754"
        score_badge = f'<span class="finding-pill" style="background:{color};">CVSS {score}</span>'

    sev_color = {"Critical": "#dc3545", "High": "#dc3545", "Medium": "#fd7e14", "Low": "#198754", "Informational": "#17a2b8", "False Positive": "#6c757d"}.get(severity, "#6c757d")
    severity_label = f'<span class="finding-pill" style="background:{sev_color};">{sanitize(severity or "INFO").upper()}</span>'

    evidence_html = f'<div class="finding-evidence"><b>Evidence:</b> {safe_evidence}</div>' if evidence else ""
    cvss_detail_html = create_cvss_detail_html(metrics)
    owasp_html = ""
    if owasp:
        owasp_id = sanitize(owasp.get("id", "N/A"))
        owasp_name = sanitize(owasp.get("name", "Uncategorized"))
        owasp_reason = sanitize(owasp.get("reason", "-"))
        owasp_html = f"""
        <div class="finding-evidence">
            <b>OWASP Top 10:2025</b><br>
            <span class="finding-pill" style="background:#0d6efd;">{owasp_id}</span>
            <b>{owasp_name}</b><br>
            <small>{owasp_reason}</small>
        </div>"""

    explanation = ""
    if danger or solution or evidence or cvss_detail_html or owasp_html:
        explanation = f"""
        <div class="finding-detail">
            {owasp_html}
            {evidence_html}
            {cvss_detail_html}
            <p><b>Analisis:</b> {safe_danger}</p>
            <p><b>Rekomendasi:</b> {safe_solution}</p>
        </div>"""

    return f"""
    <div class="finding-card" style="border-left-color:{badge_color};">
        <div class="finding-top">
            <div>
                <span class="finding-badge" style="background:{badge_color};">{sanitize(badge_text)}</span>
                {score_badge}
            </div>
            {severity_label}
        </div>
        <div class="finding-title">{safe_title}</div>
        <div class="finding-body">{safe_body}</div>
        {explanation}
    </div>"""


def get_expert_advice(finding_key):
    # Dipertahankan untuk kompatibilitas lama. Penilaian utama kini dilakukan oleh DynamicScoringEngine.
    if finding_key.startswith("port_"):
        port = int(re.sub(r"\D", "", finding_key) or 0)
        kb = get_port_entry(port)
    elif finding_key.startswith("missing_"):
        kb = get_header_entry(finding_key)
    else:
        kb = get_vuln_entry(finding_key)
    return {"name": kb.get("name", "Unknown Finding"), "score": 0.0, "severity": "Informational", "danger": kb.get("danger", "-"), "solution": kb.get("solution", "-"), "confidence": 50}


def check_ssl_details(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp_date_str = cert.get("notAfter")
                expiry_date = datetime.datetime.strptime(exp_date_str, "%b %d %H:%M:%S %Y %Z")
                days_to_expire = (expiry_date - datetime.datetime.utcnow()).days
                protocol = ssock.version()
                ev = Evidence(finding_type="ssl", target=hostname, ssl_protocol=protocol, ssl_days_remaining=days_to_expire)
                decision = SCORING.score_ssl(ev)
                title = "SSL/TLS Configuration OK"
                if days_to_expire <= 0:
                    title = "SSL Certificate Expired"
                elif days_to_expire <= 14:
                    title = "SSL Certificate Expiring Soon"
                elif protocol in ["TLSv1", "TLSv1.1"]:
                    title = f"Weak TLS Protocol: {protocol}"
                return create_card_html("🔒 SSL", "#28a745" if decision["score"] == 0 else "#fd7e14", title, f"Protocol: {sanitize(protocol)}<br>Valid until: {sanitize(exp_date_str)}", decision["score"], decision["severity"], decision["reason"], decision["solution"], decision["confidence"], f"Days remaining: {days_to_expire}", decision.get("metrics"), OwaspMapper.classify(ev))
    except Exception as e:
        return create_card_html("🔒 SSL", "#6c757d", "SSL Check Failed", f"Error: {sanitize(str(e))}", 0.0, "Informational", "SSL tidak dapat diperiksa dari koneksi saat ini.", "Periksa konektivitas dan konfigurasi TLS target.", 0, metrics=None)


def run_directory_scan(base_url):
    wordlist_path = "wordlist.txt"
    if not os.path.exists(wordlist_path):
        return []
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip().lstrip("/") for line in f if line.strip()]

    def check_path(word):
        path = f"{base_url.rstrip('/')}/{word}"
        try:
            # Jangan filter hanya status 200; 403/redirect juga butuh dianalisis.
            res = requests.get(path, timeout=4, verify=False, allow_redirects=False, headers={"User-Agent": "WebSecChecker-Scanner/3.0"})
            if res.status_code in {200, 301, 302, 307, 308, 401, 403}:
                return path
        except requests.RequestException:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        return [r for r in executor.map(check_path, words) if r]


def get_whois_scraped_html(domain):
    try:
        url = f"https://www.whois.com/whois/{domain}"
        res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10, verify=False)
        if "Domain Name:" in res.text:
            start_pos = res.text.find("Domain Name:")
            end_pos = res.text.find("</pre>", start_pos)
            whois_text = res.text[start_pos:end_pos].strip()
            whois_html = sanitize(whois_text).replace("\n", "<br>").replace(" ", "&nbsp;")
            content = f'<details><summary>Detail WHOIS</summary><div class="code-box">{whois_html}</div></details>'
            return create_card_html("🔎 WHOIS", "#20c997", "Domain Registration Data", content, 0.0, "Informational", "Data registrasi domain ditemukan sebagai informasi OSINT.", "Tidak ada tindakan keamanan langsung.", 60)
        return ""
    except requests.RequestException:
        return ""


def get_osint_subdomains_html(domain):
    subdomains = set()

    sources = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
    ]

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    # =========================
    # SOURCE 1 : CRT.SH
    # =========================
    try:
        res = requests.get(
            sources[0],
            timeout=5,
            headers=headers,
            verify=False
        )

        if res.status_code == 200:
            data = res.json()

            for item in data:
                name = item.get("name_value", "")

                for sub in name.split("\n"):
                    sub = sub.strip().lower()

                    if (
                        sub
                        and "*" not in sub
                        and domain in sub
                    ):
                        subdomains.add(sub)

    except requests.exceptions.Timeout:
        pass

    except Exception:
        pass

    # =========================
    # SOURCE 2 : HACKERTARGET
    # =========================
    try:
        res = requests.get(
            sources[1],
            timeout=5,
            headers=headers,
            verify=False
        )

        if res.status_code == 200:

            for line in res.text.splitlines():

                if "," in line:
                    sub = line.split(",")[0].strip().lower()

                    if (
                        sub
                        and "*" not in sub
                        and domain in sub
                    ):
                        subdomains.add(sub)

    except Exception:
        pass

    # =========================
    # NO RESULT
    # =========================
    if not subdomains:

        return create_card_html(
            "🔎 OSINT",
            "#6c757d",
            "Subdomain Enumeration Unavailable",
            "Tidak ada data subdomain yang berhasil diambil dari sumber OSINT.",
            0.0,
            "Informational",
            "Layanan OSINT eksternal sedang lambat atau memblokir request.",
            "Coba ulang beberapa saat lagi atau gunakan sumber OSINT lain.",
            0
        )

    # =========================
    # FORMAT OUTPUT
    # =========================
    subdomains = sorted(subdomains)

    top = "".join(
    [f"<li>{sanitize(s)}</li>" for s in subdomains]
)

    content = f"""
    <div style="max-height:400px; overflow-y:auto;">
    <ul class='compact-list'>
        {top}
    </ul>
    </div>
    """

    return create_card_html(
        "🔎 OSINT",
        "#20c997",
        f"Subdomain Enumeration ({len(subdomains)} ditemukan)",
        content,
        0.0,
        "Informational",
        "Subdomain publik berhasil ditemukan melalui sumber OSINT.",
        "Pastikan seluruh subdomain aktif dipantau dan diamankan.",
        80
    )

def perform_scan(target_url):
    hostname = normalize_hostname(target_url)
    base_url = target_url.rstrip("/") if target_url.startswith(("http://", "https://")) else f"https://{hostname}"
    formatted_cards = []
    max_score = 0.0
    overall_status = "Informational"

    def update_risk(score, severity):
        nonlocal max_score, overall_status

        # False Positive dan Informational tidak mempengaruhi tingkat risiko akhir.
        if severity in ["False Positive", "Informational"]:
            return

        # Risiko akhir ditentukan dari CVSS tertinggi dari temuan valid.
        current_score = float(score or 0.0)
        if current_score > max_score:
            max_score = current_score
            overall_status = severity

    try:
        ip_addr = socket.gethostbyname(hostname)
        formatted_cards.append(create_card_html("🌐 NETWORK", "#6c757d", "Origin Server Info", f"IP Address: {sanitize(ip_addr)}<br>Target: {sanitize(base_url)}", 0.0, "Informational", "Informasi dasar host target.", "Tidak ada tindakan langsung.", 70))
    except socket.gaierror:
        pass

    for card in [get_whois_scraped_html(hostname), get_osint_subdomains_html(hostname), check_ssl_details(hostname)]:
        if card:
            formatted_cards.append(card)

    try:
        res = requests.get(base_url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True, headers={"User-Agent": "WebSecChecker-Scanner/3.0"})
        sec_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "Content-Security-Policy": "XSS impact reduction",
            "X-Content-Type-Options": "MIME sniffing protection",
            "Strict-Transport-Security": "HTTPS downgrade protection",
            "Referrer-Policy": "Referrer data protection",
            "Permissions-Policy": "Browser feature restriction",
        }

        missing_count = 0
        present_headers = []

        for header, desc in sec_headers.items():
            if header not in res.headers:
                missing_count += 1
                ev = Evidence(finding_type="header", target=base_url, header_name=header)
                decision = SCORING.score_header(ev)
                kb = get_header_entry(header)
                formatted_cards.append(create_card_html("🛡️ HEADER", "#ffc107", f"Missing Header: {sanitize(header)}", desc, decision["score"], decision["severity"], decision["reason"], decision["solution"], decision["confidence"], "Header tidak ditemukan pada response utama", decision.get("metrics"), OwaspMapper.classify(ev)))
                update_risk(decision["score"], decision["severity"])
            else:
                present_headers.append(header)

        if missing_count == 0:
            formatted_cards.append(create_card_html(
                "🛡️ HEADER",
                "#28a745",
                "HTTP Security Headers OK",
                "Semua security headers utama terdeteksi pada response utama.",
                0.0,
                "Informational",
                "Security headers utama telah tersedia pada response utama.",
                "Pertahankan konfigurasi header keamanan dan lakukan pengecekan berkala.",
                80,
                evidence="Headers terdeteksi: " + ", ".join(present_headers),
                metrics=None,
                owasp={"id": "N/A", "name": "Informational / Hardened", "reason": "Tidak ada missing header utama pada response utama."}
            ))
    except requests.RequestException as e:
        formatted_cards.append(create_card_html(
            "🛡️ HEADER",
            "#6c757d",
            "HTTP Security Header Check Failed",
            f"Error: {sanitize(str(e))}",
            0.0,
            "Informational",
            "Pemeriksaan security headers gagal dilakukan dari koneksi scanner.",
            "Periksa koneksi target, DNS, timeout, atau proteksi WAF/CDN.",
            0,
            evidence="Header check gagal dieksekusi.",
            metrics=None,
            owasp={"id": "N/A", "name": "Scan Error", "reason": "Request gagal sehingga security headers tidak dapat diperiksa."}
        ))

    try:
        nm = nmap.PortScanner()
        scan_ports = "21,22,23,25,53,80,443,3306,3389,5432,6379,8080,8443,9200,27017"
        nm.scan(hosts=hostname, ports=scan_ports, arguments="-sV --open")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    svc = nm[host][proto][port]
                    ev = Evidence(
                        finding_type="port",
                        target=f"{port}/{proto}",
                        port_number=int(port),
                        protocol=proto,
                        service_name=svc.get("name", "unknown"),
                        service_product=svc.get("product", ""),
                        service_version=svc.get("version", ""),
                    )
                    decision = SCORING.score_port(ev)
                    body = f"Service: {sanitize(ev.service_name.upper())}"
                    if ev.service_product or ev.service_version:
                        body += f"<br>Product/Version: {sanitize(ev.service_product)} {sanitize(ev.service_version)}"
                    evidence = " | ".join(filter(None, [f"Port: {port}/{proto}", f"Service: {ev.service_name}", f"Version: {ev.service_version or '-'}", "CVSS Vector: " + "/".join(f"{k}:{v}" for k, v in decision["metrics"].items()) if decision.get("metrics") else "CVSS Vector: N/A"]))
                    formatted_cards.append(create_card_html("🔌 PORT", "#343a40", f"Open Port: {port}", body, decision["score"], decision["severity"], decision["reason"], decision["solution"], decision["confidence"], evidence, decision.get("metrics"), OwaspMapper.classify(ev)))
                    update_risk(decision["score"], decision["severity"])
    except Exception:
        pass

    smart_scanner = SmartScanner(base_url)
    for path in run_directory_scan(base_url):
        parts = path.strip().lower().split("/")
        word_clean = parts[-1] if parts[-1] else (parts[-2] if len(parts) > 1 else parts[0])
        result = smart_scanner.analyze_directory_path(path, word_clean)
        formatted_cards.append(create_card_html(
            badge_text="📁 DIR",
            badge_color=result["badge_color"],
            title=result["display_title"],
            body_content=f"Path: <a href='{sanitize(result['path'])}' target='_blank'>{sanitize(result['path'])}</a>",
            score=result["score"] if result["score"] > 0 else None,
            severity=result["severity"],
            danger=result["danger"],
            solution=result["solution"],
            confidence=result["confidence"],
            evidence=result["evidence"],
            metrics=result.get("metrics"),
            owasp=result.get("owasp"),
        ))
        update_risk(result["score"], result["severity"])

    # Normalisasi akhir berdasarkan skor CVSS tertinggi dari temuan valid.
    # False Positive dan Informational bernilai 0 dan tidak menentukan overall risk.
    if max_score >= 9.0:
        overall_status = "Critical"
    elif max_score >= 7.0:
        overall_status = "High"
    elif max_score >= 4.0:
        overall_status = "Medium"
    elif max_score > 0.0:
        overall_status = "Low"
    else:
        overall_status = "Informational"

    return {"overall_risk": overall_status, "vulnerabilities": "".join(formatted_cards)}
