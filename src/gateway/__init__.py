"""Gateway package: adapter per Hermes.Agent e implementazioni alternative."""
from src.gateway.base import AbstractGatewayAdapter, GatewayStatus
from src.gateway.hermes_adapter import HermesGatewayAdapter
from src.gateway.mock_adapter import MockGatewayAdapter

__all__ = [
    "AbstractGatewayAdapter",
    "GatewayStatus",
    "HermesGatewayAdapter",
    "MockGatewayAdapter",
]
