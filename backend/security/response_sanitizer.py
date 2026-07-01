"""Response Sanitizer — Redacts detected sensitive data from AI responses."""

from schemas import RedactionInfo
from security.response_scanner import ScanResult


def sanitize(text: str, scan_results: list[ScanResult]) -> tuple[str, list[RedactionInfo]]:
    """
    Redact all detected sensitive data from the response.
    Processes matches from end to start to preserve positions.

    Returns:
        (sanitized_text, list of RedactionInfo)
    """
    if not scan_results:
        return text, []

    # Sort by start position descending to avoid index shifting
    sorted_results = sorted(scan_results, key=lambda r: r.start, reverse=True)

    redactions: list[RedactionInfo] = []
    sanitized = text

    for result in sorted_results:
        original = result.original
        redacted = "█" * min(len(original), 12)

        # Build descriptive redaction
        if result.type in ("API Key", "API Key (OpenAI)", "API Key (Google)", "API Key (AWS)"):
            # Show first 4 chars, redact rest
            if len(original) > 8:
                redacted = original[:4] + "█" * 8
            else:
                redacted = "█" * 8
        elif result.type in ("Password", "Database Password"):
            redacted = "█" * 8
        elif result.type in ("SSN",):
            redacted = "███-██-████"
        elif result.type in ("Credit Card",):
            redacted = "████-████-████-████"
        elif result.type == "Email Address":
            parts = original.split("@")
            if len(parts) == 2:
                redacted = parts[0][:2] + "████@" + parts[1]
            else:
                redacted = "████@████.███"
        elif result.type == "JWT Token":
            redacted = "eyJ████████.████████"
        elif result.type == "Private Key":
            redacted = "-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----"
        elif result.type == "Connection String":
            redacted = "████://████:████@████/████"

        # Apply redaction
        sanitized = sanitized[:result.start] + redacted + sanitized[result.end:]

        redactions.append(RedactionInfo(
            type=result.type,
            action="Redacted",
            reason=result.reason,
            original_snippet=original[:20] + "..." if len(original) > 20 else original,
            redacted_snippet=redacted,
        ))

    return sanitized, redactions
