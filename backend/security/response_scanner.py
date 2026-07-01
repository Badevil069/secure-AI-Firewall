"""Response Scanner — Detects secrets, PII, source code in AI responses."""

import re
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    type: str  # "API Key" | "Password" | "Token" | "PII" | "Source Code"
    action: str = "Redacted"
    reason: str = ""
    original: str = ""
    start: int = 0
    end: int = 0


# Secret patterns
SECRET_PATTERNS = [
    # API Keys
    (re.compile(r"(?:api[_\s-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?", re.I), "API Key", "Response contained a potential API key that is protected by policy."),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "API Key (OpenAI)", "Response contained what appears to be an OpenAI API key."),
    (re.compile(r"\bAIza[A-Za-z0-9_\-]{35}\b"), "API Key (Google)", "Response contained what appears to be a Google API key."),
    (re.compile(r"(?:aws[_\s-]?(?:access[_\s-]?key|secret))\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{16,})['\"]?", re.I), "API Key (AWS)", "Response contained what appears to be an AWS credential."),

    # Passwords
    (re.compile(r"(?:password|passwd|pass|pwd)\s*[:=]\s*['\"]?(\S{4,})['\"]?", re.I), "Password", "Response contained confidential password information protected by policy."),
    (re.compile(r"(?:database[_\s-]?password|db[_\s-]?pass(?:word)?)\s*[:=]\s*['\"]?(\S{4,})['\"]?", re.I), "Database Password", "Response contained a database password that must be redacted."),

    # Tokens
    (re.compile(r"(?:bearer|token|auth[_\s-]?token|access[_\s-]?token|session[_\s-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})['\"]?", re.I), "Authentication Token", "Response contained an authentication token."),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"), "JWT Token", "Response contained a JSON Web Token."),

    # Connection strings
    (re.compile(r"(?:mongodb|postgres|mysql|redis|amqp)://\S+", re.I), "Connection String", "Response contained a database connection string with potential credentials."),

    # Private keys
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "Private Key", "Response contained a private cryptographic key."),

    # Environment variables
    (re.compile(r"(?:SECRET[_\s-]?KEY|PRIVATE[_\s-]?KEY|ENCRYPTION[_\s-]?KEY)\s*[:=]\s*['\"]?(\S{8,})['\"]?", re.I), "Secret Key", "Response contained a secret key value."),
]

# PII patterns
PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN", "Response contained what appears to be a Social Security Number."),
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "Credit Card", "Response contained what appears to be a credit card number."),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"), "Email Address", "Response contained an email address."),
]


def scan_secrets(text: str) -> list[ScanResult]:
    """Scan text for secrets and credentials."""
    results = []
    for pattern, secret_type, reason in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            results.append(ScanResult(
                type=secret_type,
                action="Redacted",
                reason=reason,
                original=match.group(0),
                start=match.start(),
                end=match.end(),
            ))
    return results


def scan_pii(text: str) -> list[ScanResult]:
    """Scan text for PII."""
    results = []
    for pattern, pii_type, reason in PII_PATTERNS:
        for match in pattern.finditer(text):
            results.append(ScanResult(
                type=pii_type,
                action="Redacted",
                reason=reason,
                original=match.group(0),
                start=match.start(),
                end=match.end(),
            ))
    return results


def scan_all(text: str) -> list[ScanResult]:
    """Run all scanners on the text."""
    return scan_secrets(text) + scan_pii(text)
