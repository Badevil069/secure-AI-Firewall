"""Policy Engine — Checks detection results against active firewall policies."""

from typing import Optional

# Default policies
DEFAULT_POLICIES = {
    "prompt_injection_protection": {
        "name": "Prompt Injection Protection",
        "slug": "prompt_injection_protection",
        "description": "Detects and blocks prompt injection and instruction override attacks.",
        "enabled": True,
        "categories": ["Prompt Injection", "Prompt Extraction"],
    },
    "jailbreak_protection": {
        "name": "Jailbreak Protection",
        "slug": "jailbreak_protection",
        "description": "Detects and blocks jailbreak attempts including DAN and roleplay attacks.",
        "enabled": True,
        "categories": ["Jailbreak"],
    },
    "credential_protection": {
        "name": "Credential Protection",
        "slug": "credential_protection",
        "description": "Prevents extraction of API keys, passwords, tokens, and secrets.",
        "enabled": True,
        "categories": ["Credential Theft"],
    },
    "source_code_protection": {
        "name": "Source Code Protection",
        "slug": "source_code_protection",
        "description": "Prevents leakage of source code, internal implementation, and configuration.",
        "enabled": True,
        "categories": ["Source Code Leakage"],
    },
    "data_exfiltration_protection": {
        "name": "Data Exfiltration Protection",
        "slug": "data_exfiltration_protection",
        "description": "Prevents unauthorized extraction of sensitive organizational data.",
        "enabled": True,
        "categories": ["Data Exfiltration"],
    },
    "response_sanitization": {
        "name": "Response Sanitization",
        "slug": "response_sanitization",
        "description": "Scans and redacts sensitive information in AI responses.",
        "enabled": True,
        "categories": [],
    },
    "memory_protection": {
        "name": "Memory Protection",
        "slug": "memory_protection",
        "description": "Prevents recall of sensitive information from conversation history.",
        "enabled": True,
        "categories": [],
    },
}

# Runtime policy state (can be toggled)
_active_policies: dict[str, dict] = {k: {**v} for k, v in DEFAULT_POLICIES.items()}


class PolicyResult:
    def __init__(
        self,
        should_block: bool,
        policy_name: str,
        policy_slug: str,
        reason: str,
        downgraded: bool = False,
    ):
        self.should_block = should_block
        self.policy_name = policy_name
        self.policy_slug = policy_slug
        self.reason = reason
        self.downgraded = downgraded


def check_policy(category: str, risk_score: int) -> PolicyResult:
    """Check if the detected threat category has an active policy that should block it."""

    for slug, policy in _active_policies.items():
        if category in policy.get("categories", []):
            if policy["enabled"]:
                return PolicyResult(
                    should_block=True,
                    policy_name=policy["name"],
                    policy_slug=slug,
                    reason=f"Blocked by policy: {policy['name']}",
                )
            else:
                return PolicyResult(
                    should_block=False,
                    policy_name=policy["name"],
                    policy_slug=slug,
                    reason=f"Policy '{policy['name']}' is disabled — threat downgraded to warning.",
                    downgraded=True,
                )

    # No matching policy — allow but flag as suspicious
    if category != "Safe":
        return PolicyResult(
            should_block=False,
            policy_name="None",
            policy_slug="none",
            reason=f"No active policy for category '{category}'. Request allowed with warning.",
        )

    return PolicyResult(
        should_block=False,
        policy_name="None",
        policy_slug="none",
        reason="No policy triggered. Request is safe.",
    )


def get_policies() -> list[dict]:
    """Return all policies with their current state."""
    return [
        {
            "name": p["name"],
            "slug": p["slug"],
            "description": p["description"],
            "enabled": p["enabled"],
        }
        for p in _active_policies.values()
    ]


def set_policy_state(slug: str, enabled: bool) -> bool:
    """Enable or disable a policy. Returns True if policy exists."""
    if slug in _active_policies:
        _active_policies[slug]["enabled"] = enabled
        return True
    return False


def is_response_sanitization_enabled() -> bool:
    """Check if response sanitization policy is active."""
    return _active_policies.get("response_sanitization", {}).get("enabled", True)


def is_memory_protection_enabled() -> bool:
    """Check if memory protection policy is active."""
    return _active_policies.get("memory_protection", {}).get("enabled", True)
