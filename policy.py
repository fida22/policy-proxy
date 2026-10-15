
from dataclasses import dataclass
import re

@dataclass(frozen=True)
class Rule:
    action: str
    pattern: str


def normalize_host(host: str) -> str:
    """Normalize a hostname for case-insensitive matching."""
    return host.strip().rstrip(".").lower()


def matches_domain(pattern: str, host: str) -> bool:
    """Match an exact domain or a *.example.com wildcard."""
    pattern = normalize_host(pattern)
    host = normalize_host(host)

    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith("." + suffix)

    return host == pattern


def is_allowed(host: str, rules: list[Rule]) -> bool:
    """Apply default-deny policy; any matching deny rule takes precedence."""
    host = normalize_host(host)

    if not host:
        return False

    matching_rules = [
        rule for rule in rules
        if matches_domain(rule.pattern, host)
    ]

    if any(rule.action == "deny" for rule in matching_rules):
        return False

    return any(rule.action == "allow" for rule in matching_rules)

def load_rules(filepath: str) -> list[Rule]:
    """Load and validate policy rules from a text file."""
    rules = []

    with open(filepath, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            # Ignore blank lines and comments.
            if not line or line.startswith("#"):
                continue

            parts = line.split()

            # Each rule must contain exactly an action and a pattern.
            if len(parts) != 2:
                raise ValueError(
                    f"Line {line_number}: expected ACTION DOMAIN"
                )

            action, pattern = parts
            action = action.lower()

            if action not in {"allow", "deny"}:
                raise ValueError(
                    f"Line {line_number}: invalid action '{action}'"
                )

            if not pattern:
                raise ValueError(
                    f"Line {line_number}: domain pattern is empty"
                )

            pattern = validate_domain_pattern(pattern)
            rules.append(Rule(action, pattern))

    return rules

def validate_domain_pattern(pattern: str) -> str:
    """Validate an exact domain or a *.example.com wildcard."""
    pattern = pattern.strip().lower()

    if pattern.endswith("."):
        pattern = pattern[:-1]

    if pattern.startswith("*."):
        domain = pattern[2:]
    else:
        domain = pattern

    if not domain or len(domain) > 253:
        raise ValueError(f"Invalid domain pattern: {pattern!r}")

    labels = domain.split(".")

    # Require at least two labels, such as example.com.
    if len(labels) < 2:
        raise ValueError(f"Invalid domain pattern: {pattern!r}")

    for label in labels:
        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            label,
        ):
            raise ValueError(f"Invalid domain pattern: {pattern!r}")

    # Avoid overly broad wildcard policies.
    if pattern.startswith("*.") and len(labels) < 2:
        raise ValueError(f"Invalid wildcard pattern: {pattern!r}")

    return pattern
