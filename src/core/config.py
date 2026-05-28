"""
Loader di configurazione YAML con override tramite variabili d'ambiente.

La configurazione viene letta da un file YAML e poi le variabili
d'ambiente con prefisso HERMES_IDS_ sovrascrivono i valori specifici.

Variabili d'ambiente supportate:
    HERMES_API_KEY      → hermes.api_key
    HERMES_BASE_URL     → hermes.base_url
    LOG_LEVEL           → service.log_level
    CAPTURE_INTERFACE   → capture.interface
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, model_validator


def _expand_env(text: str) -> str:
    """
    Sostituisce ${VAR} e ${VAR:-default} con i valori delle variabili d'ambiente.
    Usato prima del parsing YAML per supportare configurazione via .env / Docker.
    """
    def _sub(m: re.Match) -> str:
        var     = m.group(1)
        default = m.group(2) if m.group(2) is not None else ""
        return os.environ.get(var, default)

    # Gruppo 1: nome variabile  Gruppo 2: valore default (dopo :-)
    return re.sub(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}", _sub, text)


# ─── Sub-configurazioni ──────────────────────────────────────────────────────

class ServiceConfig(BaseModel):
    name: str = "hermes-ids"
    version: str = "0.1.0"
    log_level: str = "INFO"
    log_format: str = "json"  # json | console


class CaptureConfig(BaseModel):
    interface: str = "auto"
    promiscuous: bool = True
    bpf_filter: str = ""
    arp_poll_interval: int = 30


class QueueConfig(BaseModel):
    max_size: int = 10_000
    drain_interval: float = 0.1


class RateLimiterConfig(BaseModel):
    enabled: bool = True
    max_events_per_second: int = 100
    burst_size: int = 200


# ── Detector configs ─────────────────────────────────────────────────────────

class PortScanConfig(BaseModel):
    enabled: bool = True
    window_seconds: int = 10
    min_ports: int = 10
    severity: str = "high"


class NewHostConfig(BaseModel):
    enabled: bool = True
    known_hosts_file: str = "config/known_hosts.yaml"
    severity: str = "medium"


class TrafficVolumeConfig(BaseModel):
    enabled: bool = True
    window_seconds: int = 60
    threshold_pps: int = 5_000
    threshold_bps: int = 10_000_000  # 10 Mbit/s
    severity: str = "medium"


class SensitivePortsConfig(BaseModel):
    enabled: bool = True
    ports: List[int] = Field(
        default_factory=lambda: [22, 23, 3389, 5900, 445, 135, 139, 1433, 3306, 5432]
    )
    window_seconds: int = 60
    min_attempts: int = 5
    severity: str = "high"


class ARPSpoofConfig(BaseModel):
    enabled: bool = True
    window_seconds: int = 10
    severity: str = "critical"


class DetectorsConfig(BaseModel):
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    new_host: NewHostConfig = Field(default_factory=NewHostConfig)
    traffic_volume: TrafficVolumeConfig = Field(default_factory=TrafficVolumeConfig)
    sensitive_ports: SensitivePortsConfig = Field(default_factory=SensitivePortsConfig)
    arp_spoof: ARPSpoofConfig = Field(default_factory=ARPSpoofConfig)


class PluginsConfig(BaseModel):
    enabled: bool = True
    directory: str = "plugins"


# ── Hermes gateway ───────────────────────────────────────────────────────────

class HermesRetryConfig(BaseModel):
    max_attempts: int = 5
    min_wait_seconds: float = 1.0
    max_wait_seconds: float = 30.0
    multiplier: float = 2.0


class HermesReconnectConfig(BaseModel):
    enabled: bool = True
    interval_seconds: float = 15.0


class HermesReportConfig(BaseModel):
    """Configurazione per i report periodici inviati su Telegram (bypass LLM)."""
    enabled: bool = True
    webhook_path: str = "/webhooks/ids-report"
    secret: str = ""
    interval_seconds: int = 600       # report ogni 10 minuti
    max_events: int = 15              # eventi mostrati per report
    startup_delay_seconds: int = 60   # attesa dopo startup prima del primo report


class HermesConfig(BaseModel):
    enabled: bool = True
    adapter: str = "websocket"  # websocket | webhook | mock
    base_url: str = "ws://localhost:8080"
    publish_path: str = "/ws/events"
    api_key: str = ""
    timeout_seconds: int = 10
    retry: HermesRetryConfig = Field(default_factory=HermesRetryConfig)
    reconnect: HermesReconnectConfig = Field(default_factory=HermesReconnectConfig)
    report: HermesReportConfig = Field(default_factory=HermesReportConfig)


# ── API & Metrics ─────────────────────────────────────────────────────────────

class APIConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8765
    workers: int = 1
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])
    events_history_size: int = 1000


class MetricsConfig(BaseModel):
    enabled: bool = True
    path: str = "/metrics"
    port: int = 9090


# ─── Root config ─────────────────────────────────────────────────────────────

class AppConfig(BaseModel):
    """
    Configurazione completa dell'applicazione.

    Caricamento::

        config = AppConfig.from_yaml("config/config.yaml")
    """

    service: ServiceConfig = Field(default_factory=ServiceConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    queue: QueueConfig = Field(default_factory=QueueConfig)
    rate_limiter: RateLimiterConfig = Field(default_factory=RateLimiterConfig)
    detectors: DetectorsConfig = Field(default_factory=DetectorsConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    hermes: HermesConfig = Field(default_factory=HermesConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "AppConfig":
        """
        Carica configurazione da file YAML.

        Le variabili d'ambiente sovrascrivono i valori del file:
            HERMES_API_KEY        → hermes.api_key
            HERMES_BASE_URL       → hermes.base_url
            LOG_LEVEL             → service.log_level
            CAPTURE_INTERFACE     → capture.interface
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path, encoding="utf-8") as f:
            raw_text = f.read()

        # Espande ${VAR:-default} prima del parsing YAML
        raw_text = _expand_env(raw_text)
        raw: Dict[str, Any] = yaml.safe_load(raw_text) or {}

        config = cls(**raw)

        # Env override esplicito (retrocompatibilità + priorità assoluta)
        if api_key := os.environ.get("HERMES_EVENTS_SECRET", os.environ.get("HERMES_API_KEY")):
            config.hermes.api_key = api_key
        if base_url := os.environ.get("HERMES_GATEWAY_URL", os.environ.get("HERMES_BASE_URL")):
            config.hermes.base_url = base_url
        if report_secret := os.environ.get("HERMES_REPORT_SECRET"):
            config.hermes.report.secret = report_secret
        if report_interval := os.environ.get("HERMES_REPORT_INTERVAL"):
            config.hermes.report.interval_seconds = int(report_interval)
        if log_level := os.environ.get("LOG_LEVEL"):
            config.service.log_level = log_level.upper()
        if iface := os.environ.get("CAPTURE_INTERFACE"):
            config.capture.interface = iface

        return config

    @classmethod
    def default(cls) -> "AppConfig":
        """Configurazione di default (utile per test)."""
        return cls()
