"""
Detectors package.

Import espliciti per garantire la registrazione automatica di tutti
i detector built-in nel registry globale al momento dell'import.
"""
from src.detectors.base import BaseDetector, get_detector_registry, register_detector
from src.detectors.arp_spoof import ARPSpoofDetector
from src.detectors.new_host import NewHostDetector
from src.detectors.port_scan import PortScanDetector
from src.detectors.sensitive_ports import SensitivePortsDetector
from src.detectors.traffic_volume import TrafficVolumeDetector

__all__ = [
    "BaseDetector",
    "register_detector",
    "get_detector_registry",
    "ARPSpoofDetector",
    "NewHostDetector",
    "PortScanDetector",
    "SensitivePortsDetector",
    "TrafficVolumeDetector",
]
