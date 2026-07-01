import re
import sys
sys.path.append(r"c:\Users\abhia\.gemini\antigravity-ide\scratch\security-ai\backend")
from schemas import DetectionResult

HACKING_PATTERNS = [
    r"\bhow\s+to\s+hack\b",
    r"\bhelp\s+me\s+hack\b",
    r"\bi\s+need\s+to\s+hack\b",
    r"\bwant\s+to\s+hack\b",
    r"\bhack\s+\w+\s+system\b",
    r"\bhack\s+\w+\s+account\b",
    r"\bhack\s+\w+\s+password\b",
    r"\bcrack\s+\w+\s+password\b",
    r"\bbrute.?force\b",
    r"\bbypass\s+\w*\s*security\b",
    r"\bgain\s+\w*\s*unauthorized\s+access\b",
    r"\bunauthorized\s+access\b",
    r"\bbreak\s+into\b",
    r"\bget\s+into\s+someone\b",
    r"\baccess\s+someone\s+else\b",
    r"\bpenetrat(e|ion)\b",
    r"\bphish(ing)?\b",
    r"\bsocial\s+engineer(ing)?\b",
    r"\bddos\b",
    r"\bdos\s+attack\b",
    r"\bmalware\b",
    r"\bransomware\b",
    r"\bkeylogger\b",
    r"\btrojan\s+(horse|virus)?\b",
    r"\bsql\s*inject(ion)?\b",
    r"\bcross\s+site\s+script\b",
    r"\bxss\s+attack\b",
    r"\bman\s+in\s+the\s+middle\b",
    r"\bmitm\b",
    r"\bsniff\s+\w*\s*traffic\b",
    r"\breverse\s+shell\b",
    r"\bprivilege\s+escalat(ion|e)\b",
    r"\bzero.?day\s+(exploit|vulnerability)?\b",
    r"\bexploit\s+\w*\s*(vulnerability|system|server)\b",
    r"\bbypass\s+\w*\s*(firewall|authentication|login|2fa|mfa)\b",
    r"\bsteal\s+\w*\s*(data|credentials|password|token)\b",
    r"\bscrape\s+\w*\s*(data|credentials)\b",
    r"\bintercept\s+\w*\s*(traffic|data|communication)\b",
    r"\bspy\s+on\b",
    r"\bsurveillance\s+on\b",
    r"\btrack\s+someone\b",
    r"\bmonitor\s+someone\s+without\b",
    # Additional patterns
    r"\bown\s+\w+\s+server\b",
    r"\bpwn\b",
    r"\broot\s+access\b",
    r"\bshell\s+access\b",
    r"\bremote\s+access\s+without\b",
    r"\bbypass\s+\w*\s*login\b",
    r"\bdump\s+\w*\s*(database|credentials|hashes)\b",
    r"\bpassword\s+dump\b",
    r"\bhash\s+crack\b",
    r"\bwifi\s+password\b",
    r"\bnetwork\s+sniff\b",
]

def detect(prompt: str) -> DetectionResult:
    prompt_lower = prompt.lower()
    for pattern in HACKING_PATTERNS:
        match = re.search(pattern, prompt_lower)
        if match:
            return DetectionResult(
                detector="Hacking Attempt Detector",
                detected=True,
                confidence=0.92,
                matched_pattern=match.group(),
                category="HACKING_ATTEMPT",
                reason=f"Hacking-related pattern detected: '{match.group()}'"
            )
    return DetectionResult(
        detector="Hacking Attempt Detector",
        detected=False,
        confidence=0.0,
        category="Safe"
    )
