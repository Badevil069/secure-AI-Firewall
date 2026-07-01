"""Request Firewall — Entry gate for all incoming prompts."""

import re
import time
from schemas import DetectionResult


# Basic input sanitization
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_EXCESSIVE_WHITESPACE = re.compile(r"\s{10,}")

# Encoding-based evasion patterns
_ENCODING_EVASION = [
    (re.compile(r"\\x[0-9a-fA-F]{2}"), "Hex encoding evasion"),
    (re.compile(r"\\u[0-9a-fA-F]{4}"), "Unicode encoding evasion"),
    (re.compile(r"%[0-9a-fA-F]{2}"), "URL encoding evasion"),
    (re.compile(r"&#\d+;"), "HTML entity evasion"),
    (re.compile(r"\\[nrt]"), "Escape sequence evasion"),
]


class RequestFirewallResult:
    def __init__(
        self,
        passed: bool,
        sanitized_prompt: str,
        original_prompt: str,
        warnings: list[str] | None = None,
        blocked_reason: str = "",
    ):
        self.passed = passed
        self.sanitized_prompt = sanitized_prompt
        self.original_prompt = original_prompt
        self.warnings = warnings or []
        self.blocked_reason = blocked_reason


def validate(prompt: str) -> RequestFirewallResult:
    """Validate and sanitize the incoming prompt at the firewall level."""
    original = prompt
    warnings: list[str] = []

    # ── Length check ──
    if len(prompt) > 4096:
        return RequestFirewallResult(
            passed=False,
            sanitized_prompt="",
            original_prompt=original,
            blocked_reason="Prompt exceeds maximum length of 4096 characters.",
        )

    if len(prompt.strip()) == 0:
        return RequestFirewallResult(
            passed=False,
            sanitized_prompt="",
            original_prompt=original,
            blocked_reason="Empty prompt.",
        )

    # ── Strip control characters ──
    cleaned = _CONTROL_CHARS.sub("", prompt)
    if cleaned != prompt:
        warnings.append("Control characters removed from input.")
        prompt = cleaned

    # ── Collapse excessive whitespace ──
    cleaned = _EXCESSIVE_WHITESPACE.sub("  ", prompt)
    if cleaned != prompt:
        warnings.append("Excessive whitespace collapsed.")
        prompt = cleaned

    # ── Check for encoding evasion ──
    for pattern, description in _ENCODING_EVASION:
        if pattern.search(prompt):
            warnings.append(f"Potential {description} detected.")

    return RequestFirewallResult(
        passed=True,
        sanitized_prompt=prompt.strip(),
        original_prompt=original,
        warnings=warnings,
    )
