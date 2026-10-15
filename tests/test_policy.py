
from policy import Rule, matches_domain, is_allowed
from policy import load_rules
from policy import validate_domain_pattern
def test_exact_domain_match():
    assert matches_domain("example.com", "example.com")
    assert not matches_domain("example.com", "www.example.com")
    assert not matches_domain("example.com", "notexample.com")


def test_wildcard_matches_subdomains_only():
    assert matches_domain("*.wikipedia.org", "en.wikipedia.org")
    assert matches_domain("*.wikipedia.org", "a.b.wikipedia.org")
    assert not matches_domain("*.wikipedia.org", "wikipedia.org")


def test_matching_is_case_insensitive():
    assert matches_domain("Example.COM", "EXAMPLE.com")


def test_trailing_dot_is_normalized():
    assert matches_domain("example.com", "example.com.")


def test_default_deny():
    rules = [Rule("allow", "example.com")]
    assert not is_allowed("unknown.com", rules)


def test_allow_rule():
    rules = [Rule("allow", "example.com")]
    assert is_allowed("example.com", rules)


def test_deny_overrides_allow():
    rules = [
        Rule("allow", "*.example.com"),
        Rule("deny", "blocked.example.com"),
    ]
    assert is_allowed("www.example.com", rules)
    assert not is_allowed("blocked.example.com", rules)


import pytest


def test_load_rules(tmp_path):
    rules_file = tmp_path / "rules.txt"
    rules_file.write_text(
        "# Example policy\n"
        "\n"
        "allow example.com\n"
        "deny *.badsite.com\n",
        encoding="utf-8",
    )

    rules = load_rules(str(rules_file))

    assert rules == [
        Rule("allow", "example.com"),
        Rule("deny", "*.badsite.com"),
    ]


def test_invalid_action_is_rejected(tmp_path):
    rules_file = tmp_path / "rules.txt"
    rules_file.write_text("block example.com\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid action"):
        load_rules(str(rules_file))


def test_malformed_rule_is_rejected(tmp_path):
    rules_file = tmp_path / "rules.txt"
    rules_file.write_text("allow\n", encoding="utf-8")

    with pytest.raises(ValueError, match="expected ACTION DOMAIN"):
        load_rules(str(rules_file))




def test_valid_domain_patterns():
    assert validate_domain_pattern("example.com") == "example.com"
    assert validate_domain_pattern("*.wikipedia.org") == "*.wikipedia.org"
    assert validate_domain_pattern("EXAMPLE.COM") == "example.com"


def test_invalid_domain_patterns():
    invalid_patterns = [
        "",
        "example..com",
        "*.com",
        "bad host.com",
        "-example.com",
        "example-.com",
        "example",
    ]

    for pattern in invalid_patterns:
        with pytest.raises(ValueError):
            validate_domain_pattern(pattern)


def test_trailing_dot_is_normalized_in_pattern():
    assert validate_domain_pattern("example.com.") == "example.com"
