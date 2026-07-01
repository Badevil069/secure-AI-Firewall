"""Trust Engine — Computes trust score (0-100) as inverse of risk with session history."""

from collections import defaultdict

# Session history tracking
_session_history: dict[str, list[int]] = defaultdict(list)


def compute_trust_score(risk_score: int, session_id: str = "default") -> int:
    """
    Compute trust score as intelligent inverse of risk.

    - Per-prompt trust = 100 - risk
    - Session trust degrades with repeated malicious prompts
    - Session trust recovers slowly with safe prompts
    """
    per_prompt_trust = max(0, 100 - risk_score)

    # Track in session history
    _session_history[session_id].append(risk_score)

    # Compute session adjustment
    history = _session_history[session_id]
    if len(history) <= 1:
        return per_prompt_trust

    # Count high-risk prompts in session
    high_risk_count = sum(1 for r in history if r >= 60)
    total = len(history)

    # Each high-risk prompt degrades session trust by 5 (max -30)
    session_penalty = min(high_risk_count * 5, 30)

    # Safe prompts provide small recovery
    safe_count = sum(1 for r in history if r < 15)
    session_recovery = min(safe_count * 2, 10)

    session_trust = max(0, per_prompt_trust - session_penalty + session_recovery)
    return min(session_trust, 100)


def get_session_risk(session_id: str = "default") -> float:
    """Get the average risk score for a session."""
    history = _session_history.get(session_id, [])
    if not history:
        return 0.0
    return round(sum(history) / len(history), 1)


def reset_session(session_id: str = "default") -> None:
    """Reset session history."""
    _session_history.pop(session_id, None)
