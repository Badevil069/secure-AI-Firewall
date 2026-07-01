"""Response Firewall — Orchestrates response scanning pipeline."""

from schemas import RedactionInfo
from security import response_scanner, response_sanitizer
from security.policy_engine import is_response_sanitization_enabled


async def scan_and_sanitize(response_text: str) -> tuple[str, list[RedactionInfo]]:
    """
    Run the response through the firewall pipeline:
    1. Scan for secrets
    2. Scan for PII
    3. Sanitize (redact) detected items

    Returns:
        (sanitized_response, list of RedactionInfo)
    """
    if not is_response_sanitization_enabled():
        return response_text, []

    # Run all scanners
    scan_results = response_scanner.scan_all(response_text)

    if not scan_results:
        return response_text, []

    # Sanitize
    sanitized, redactions = response_sanitizer.sanitize(response_text, scan_results)

    return sanitized, redactions
