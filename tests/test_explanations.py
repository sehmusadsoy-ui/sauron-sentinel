"""Guidance covers shipped heuristics and never invents a sensor or a diagnosis."""

import pytest

from sauron_sentinel.explanations import EXPLANATION_SCHEMA_VERSION, explanation_for
from sauron_sentinel.rules import load_rules


@pytest.mark.parametrize("rule", load_rules(), ids=lambda rule: rule.id)
def test_every_bundled_rule_has_versioned_turkish_guidance(rule):
    result = explanation_for(rule.id)
    assert result.keys() == {
        "schema_version",
        "rule_id",
        "summary",
        "why",
        "benign_causes",
        "checks",
    }
    assert result["schema_version"] == EXPLANATION_SCHEMA_VERSION == 1
    assert result["rule_id"] == rule.id
    assert "katalogda açıklama bulunmuyor" not in result["summary"]
    assert rule.kind in result["why"]
    assert all(type(result[field]) is str and result[field] for field in ("summary", "why"))
    for field in ("benign_causes", "checks"):
        assert type(result[field]) is list and len(result[field]) >= 2
        assert all(type(value) is str and value for value in result[field])


def test_unknown_rule_has_truthful_fallback_and_unchanged_id():
    result = explanation_for("custom-local-rule")
    assert result["rule_id"] == "custom-local-rule"
    assert "katalogda açıklama bulunmuyor" in result["summary"]
    assert "koşulları bu katalogda tanımlı değil" in result["why"]
    assert "bilinmiyor" in result["benign_causes"][0]
    assert "doğrulanmış bir saldırı" in result["summary"]


def test_catalog_results_are_detached_and_rules_remain_unchanged():
    before = load_rules()
    result = explanation_for("windows-service-installed")
    original = explanation_for("windows-service-installed")
    result["summary"] = "changed"
    result["benign_causes"].clear()
    result["checks"].append("changed")
    assert explanation_for("windows-service-installed") == original
    assert load_rules() == before
    unknown = explanation_for("custom-local-rule")
    unknown["checks"].clear()
    assert explanation_for("another-rule")["checks"]


def test_guidance_tracks_thresholds_and_conditions():
    why = explanation_for("auth-failure-burst")["why"]
    assert all(value in why for value in ("aynı cihaz ve kullanıcı", "60 saniye", "en az 5"))
    why = explanation_for("rf-activity-burst")["why"]
    assert all(value in why for value in ("10 saniye", "en az 3", "attributes.rssi_dbm >= -40"))
    why = explanation_for("motion-without-maintenance")["why"]
    assert "attributes.motion_score >= 0.8" in why
    assert "attributes.maintenance = false" in why
    for rule in load_rules():
        if rule.id.startswith("windows-"):
            assert "tek bir kayıt" in explanation_for(rule.id)["why"]


def test_guidance_avoids_confirmed_attacks_and_fabricated_integration():
    service = explanation_for("windows-service-installed")
    assert "normal" in service["summary"] and "doğrulamaz" in service["summary"]
    assert "dijital imzayı değerlendirmez" in service["why"]
    defender = explanation_for("windows-defender-disabled")
    assert "şu anda kapalı olduğunu doğrulamaz" in defender["summary"]
    group = explanation_for("windows-group-member-added")
    assert "Her grup değişikliği" in group["summary"]
    for rule_id in ("rf-activity-burst", "motion-without-maintenance"):
        assert "Canlı Windows izleyicisi" in explanation_for(rule_id)["summary"]
        assert "CSI" in explanation_for(rule_id)["summary"]
    for rule in load_rules():
        checks = " ".join(explanation_for(rule.id)["checks"]).lower()
        assert not any(
            value in checks
            for value in ("yönetici olarak çalıştır", "devre dışı bırak", "güvenlik duvarını kapat")
        )
