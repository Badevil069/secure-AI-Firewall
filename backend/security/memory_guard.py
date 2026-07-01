"""Memory Guard — AI Memory Shield that prevents recall of sensitive data."""

import re
from collections import defaultdict
from security.policy_engine import is_memory_protection_enabled

# Session memory stores
_sensitive_memories: dict[str, list[str]] = defaultdict(list)

# Patterns that indicate a user is sharing sensitive data
SENSITIVE_SHARE_PATTERNS = [
    (re.compile(r"(?:my|the)\s+password\s+is\s+(\S+)", re.I), "password"),
    (re.compile(r"(?:my|the)\s+(?:api[_\s]?key|apikey)\s+is\s+(\S+)", re.I), "api_key"),
    (re.compile(r"(?:my|the)\s+secret\s+is\s+(\S+)", re.I), "secret"),
    (re.compile(r"(?:my|the)\s+token\s+is\s+(\S+)", re.I), "token"),
    (re.compile(r"(?:my|the)\s+ssn\s+is\s+(\S+)", re.I), "ssn"),
    (re.compile(r"remember\s+(?:my|this|the)\s+(?:password|secret|key|token|credential)", re.I), "credential"),
    (re.compile(r"(?:my|the)\s+credit\s+card\s+(?:number\s+)?is\s+(\S+)", re.I), "credit_card"),
    (re.compile(r"(?:my|the)\s+(?:pin|PIN)\s+is\s+(\S+)", re.I), "pin"),
]

# Patterns that indicate a user is trying to recall sensitive data
RECALL_PATTERNS = [
    re.compile(r"what\s+(?:is|was|were)\s+(?:my|the)\s+(?:password|secret|key|token|credential|pin|ssn)", re.I),
    re.compile(r"(?:recall|remember|repeat|tell\s+me|what\s+(?:did\s+)?i\s+(?:tell|share|give))\s+.{0,20}(?:password|secret|key|token|credential|sensitive)", re.I),
    re.compile(r"what\s+(?:secrets?|passwords?|credentials?|keys?)\s+(?:do\s+)?you\s+(?:know|remember|have|store)", re.I),
    re.compile(r"(?:list|show|display)\s+(?:all\s+)?(?:stored|remembered|saved)\s+(?:secrets?|passwords?|credentials?)", re.I),
    re.compile(r"what\s+sensitive\s+(?:info|information|data)\s+(?:do\s+)?you\s+(?:have|remember|know)", re.I),
]


def check_for_sensitive_share(prompt: str, session_id: str = "default") -> bool:
    """Check if the user is sharing sensitive data and store it."""
    if not is_memory_protection_enabled():
        return False

    found = False
    for pattern, data_type in SENSITIVE_SHARE_PATTERNS:
        match = pattern.search(prompt)
        if match:
            _sensitive_memories[session_id].append(data_type)
            found = True

    return found


def check_for_recall_attempt(prompt: str, session_id: str = "default") -> tuple[bool, str]:
    """
    Check if the user is trying to recall sensitive data.

    Returns:
        (is_recall_attempt, reason)
    """
    if not is_memory_protection_enabled():
        return False, ""

    for pattern in RECALL_PATTERNS:
        if pattern.search(prompt):
            has_sensitive = bool(_sensitive_memories.get(session_id))
            if has_sensitive:
                types = set(_sensitive_memories[session_id])
                return True, (
                    f"Memory Shield activated. Sensitive data ({', '.join(types)}) was previously "
                    f"shared in this session. Recall of sensitive information is blocked by policy."
                )
            else:
                return True, (
                    "Memory Shield activated. This prompt attempts to recall sensitive information "
                    "from conversation history. This action is blocked by Memory Protection policy."
                )

    return False, ""


def reset_memory(session_id: str = "default") -> None:
    """Clear sensitive memory for a session."""
    _sensitive_memories.pop(session_id, None)
