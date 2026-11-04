"""Rule files are a bounded declarative format, never executable code."""

import pytest

from sauron_sentinel.models import ValidationError
from sauron_sentinel.rules import load_rules


def test_bundled_rules_have_unique_identifiers():
    rules = load_rules()
    assert len(rules) == 3
    assert len({rule.id for rule in rules}) == 3


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("schema_version = 1", "schema_version = 2"),
        ('severity = "medium"', 'severity = "urgent"'),
        ("threshold = 2", "threshold = 0"),
        ("threshold = 2", "threshold = true"),
        ("threshold = 2", "threshold = 10001"),
        ("window_seconds = 10", "window_seconds = 0"),
        ("window_seconds = 10", "window_seconds = inf"),
        ("cooldown_seconds = 20", "cooldown_seconds = -1"),
        ('id = "test-rule"', 'id = "bad id!"'),
        ('kind = "auth.failure"', 'kind = ""'),
        ("conditions = []", 'conditions = [{field="attributes.x", op="eval", value=1}]'),
        ("conditions = []", 'conditions = [{field="__class__", op="eq", value=1}]'),
        ("conditions = []", 'conditions = [{field="attributes.x", op="eq"}]'),
    ],
)
def test_invalid_rules_are_rejected(rules_file, old, new):
    path = rules_file()
    contents = path.read_text(encoding="utf-8")
    assert old in contents
    path.write_text(contents.replace(old, new), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_rules(path)


def test_duplicate_rule_ids_are_rejected(rules_file):
    path = rules_file()
    content = path.read_text(encoding="utf-8")
    path.write_text(content + content[content.index("[[rules]]") :], encoding="utf-8")
    with pytest.raises(ValidationError):
        load_rules(path)


def test_unknown_options_are_rejected(rules_file):
    path = rules_file()
    path.write_text(path.read_text(encoding="utf-8") + "execute = 'arbitrary'\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_rules(path)


def test_malformed_toml_is_actionable(tmp_path):
    path = tmp_path / "broken.toml"
    path.write_text("[[rules]\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_rules(path)


@pytest.mark.parametrize("form", ["array", "table"])
def test_excessive_toml_nesting_is_a_validation_error(tmp_path, form):
    path = tmp_path / "deep.toml"
    nested = "[" * 600 + "1" + "]" * 600 if form == "array" else "{x=" * 600 + "1" + "}" * 600
    path.write_text("schema_version=1\nrules=" + nested, encoding="utf-8")
    with pytest.raises(ValidationError):
        load_rules(path)
