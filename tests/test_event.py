"""
Test per IDSEvent e modello dati core.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.core.event import IDSEvent, Severity, new_event


class TestSeverity:
    def test_values(self):
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_weight_ordering(self):
        assert Severity.LOW.weight < Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight < Severity.HIGH.weight
        assert Severity.HIGH.weight < Severity.CRITICAL.weight

    def test_from_string(self):
        assert Severity("high") == Severity.HIGH


class TestIDSEvent:
    def test_default_id_generated(self):
        event = new_event("test", Severity.LOW, "1.2.3.4", "test")
        assert event.id.startswith("evt-")
        assert len(event.id) > 4

    def test_unique_ids(self):
        e1 = new_event("test", Severity.LOW, "1.2.3.4", "test")
        e2 = new_event("test", Severity.LOW, "1.2.3.4", "test")
        assert e1.id != e2.id

    def test_timestamp_is_utc(self):
        event = new_event("test", Severity.LOW, "1.2.3.4", "test")
        assert event.timestamp.tzinfo is not None
        assert event.timestamp.tzinfo == timezone.utc

    def test_to_json_dict(self):
        event = new_event(
            detector_name="port_scan_detector",
            severity=Severity.HIGH,
            source_ip="192.168.1.50",
            destination_ip="192.168.1.1",
            summary="Port scan detected",
            raw_data={"ports": [22, 80]},
            tags=["network", "scan"],
        )
        d = event.to_json_dict()

        assert d["detector_name"] == "port_scan_detector"
        assert d["severity"] == "high"
        assert d["source_ip"] == "192.168.1.50"
        assert d["destination_ip"] == "192.168.1.1"
        assert d["summary"] == "Port scan detected"
        assert d["raw_data"] == {"ports": [22, 80]}
        assert d["tags"] == ["network", "scan"]
        assert isinstance(d["timestamp"], str)  # ISO string
        assert "T" in d["timestamp"]

    def test_optional_destination_ip(self):
        event = new_event("test", Severity.LOW, "1.2.3.4", "test")
        assert event.destination_ip is None
        d = event.to_json_dict()
        assert d["destination_ip"] is None

    def test_default_raw_data_empty(self):
        event = new_event("test", Severity.LOW, "1.2.3.4", "test")
        assert event.raw_data == {}

    def test_default_tags_empty(self):
        event = new_event("test", Severity.LOW, "1.2.3.4", "test")
        assert event.tags == []

    def test_str_representation(self):
        event = new_event("port_scan_detector", Severity.HIGH, "10.0.0.1", "Scan!")
        s = str(event)
        assert "HIGH" in s
        assert "port_scan_detector" in s
        assert "10.0.0.1" in s

    def test_severity_validation(self):
        with pytest.raises(Exception):
            IDSEvent(
                severity="invalid",
                source_ip="1.2.3.4",
                detector_name="test",
                summary="test",
            )

    def test_full_example_matches_spec(self):
        """Verifica che l'evento corrisponda all'esempio nella specifica."""
        event = IDSEvent(
            id="evt-001",
            severity=Severity.HIGH,
            source_ip="192.168.1.50",
            destination_ip="192.168.1.1",
            detector_name="port_scan_detector",
            summary="Possible port scan detected",
            raw_data={},
            tags=["network", "scan"],
        )
        d = event.to_json_dict()
        assert d["id"] == "evt-001"
        assert d["severity"] == "high"
        assert d["detector_name"] == "port_scan_detector"
