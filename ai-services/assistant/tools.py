"""
Assistant Tools

Tools/functions that the assistant can call to perform VPN operations.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

# Add parent for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import DELTA_S, TAU


@dataclass
class ToolParameter:
    """Definition of a tool parameter."""
    name: str
    type: str  # "string", "integer", "boolean", "number"
    description: str
    required: bool = True
    default: Any = None
    enum: Optional[List[str]] = None


@dataclass
class AssistantTool:
    """Definition of a tool the assistant can use."""
    name: str
    description: str
    parameters: List[ToolParameter] = field(default_factory=list)
    handler: Optional[Callable[..., Any]] = None

    def to_schema(self) -> Dict[str, Any]:
        """Convert to JSON schema for API calls."""
        properties = {}
        required = []

        for param in self.parameters:
            prop = {
                "type": param.type,
                "description": param.description,
            }
            if param.enum:
                prop["enum"] = param.enum
            properties[param.name] = prop

            if param.required:
                required.append(param.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }

    def execute(self, **kwargs) -> Any:
        """Execute the tool with given arguments."""
        if self.handler is None:
            return {"error": f"No handler for tool {self.name}"}
        return self.handler(**kwargs)


class ToolRegistry:
    """Registry of available tools."""

    def __init__(self):
        """Initialize tool registry."""
        self._tools: Dict[str, AssistantTool] = {}

    def register(self, tool: AssistantTool) -> None:
        """Register a tool."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[AssistantTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> List[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def get_all_schemas(self) -> List[Dict[str, Any]]:
        """Get schemas for all tools."""
        return [tool.to_schema() for tool in self._tools.values()]

    def execute(self, name: str, **kwargs) -> Any:
        """Execute a tool by name."""
        tool = self._tools.get(name)
        if tool is None:
            return {"error": f"Unknown tool: {name}"}
        return tool.execute(**kwargs)


class VPNTools:
    """
    VPN-specific tools for the assistant.

    These tools simulate VPN operations for the assistant to use.
    In production, these would connect to actual VPN services.
    """

    def __init__(self):
        """Initialize VPN tools."""
        self.registry = ToolRegistry()
        self._register_tools()

        # Simulated state
        self._connected = False
        self._current_server: Optional[str] = None
        self._privacy_level = "STANDARD"
        self._servers = self._get_mock_servers()

    def _register_tools(self) -> None:
        """Register all VPN tools."""

        # Connect tool
        self.registry.register(AssistantTool(
            name="vpn_connect",
            description="Connect to a VPN server",
            parameters=[
                ToolParameter(
                    name="server_id",
                    type="string",
                    description="Server ID to connect to (optional, auto-selects if not provided)",
                    required=False,
                ),
                ToolParameter(
                    name="privacy_level",
                    type="string",
                    description="Privacy level to use",
                    required=False,
                    default="STANDARD",
                    enum=["MINIMAL", "STANDARD", "ENHANCED", "MAXIMUM", "PARANOID"],
                ),
            ],
            handler=self._connect,
        ))

        # Disconnect tool
        self.registry.register(AssistantTool(
            name="vpn_disconnect",
            description="Disconnect from the VPN",
            parameters=[],
            handler=self._disconnect,
        ))

        # Status tool
        self.registry.register(AssistantTool(
            name="vpn_status",
            description="Get current VPN connection status",
            parameters=[],
            handler=self._status,
        ))

        # List servers tool
        self.registry.register(AssistantTool(
            name="vpn_list_servers",
            description="List available VPN servers",
            parameters=[
                ToolParameter(
                    name="region",
                    type="string",
                    description="Filter by region (e.g., 'US', 'EU', 'Asia')",
                    required=False,
                ),
            ],
            handler=self._list_servers,
        ))

        # Set privacy level tool
        self.registry.register(AssistantTool(
            name="vpn_set_privacy",
            description="Set the privacy level",
            parameters=[
                ToolParameter(
                    name="level",
                    type="string",
                    description="Privacy level to set",
                    required=True,
                    enum=["MINIMAL", "STANDARD", "ENHANCED", "MAXIMUM", "PARANOID"],
                ),
            ],
            handler=self._set_privacy,
        ))

        # Get routing info tool
        self.registry.register(AssistantTool(
            name="vpn_routing_info",
            description="Get silver routing information for current connection",
            parameters=[],
            handler=self._routing_info,
        ))

        # Check threat status tool
        self.registry.register(AssistantTool(
            name="vpn_threat_check",
            description="Check current threat detection status",
            parameters=[],
            handler=self._threat_check,
        ))

        # Explain silver concept tool
        self.registry.register(AssistantTool(
            name="explain_silver",
            description="Get explanation of a silver ratio concept",
            parameters=[
                ToolParameter(
                    name="concept",
                    type="string",
                    description="The concept to explain",
                    required=True,
                    enum=["silver_ratio", "pell_sequence", "eta_lambda", "silver_timing", "traffic_balance"],
                ),
            ],
            handler=self._explain_silver,
        ))

    def _get_mock_servers(self) -> List[Dict[str, Any]]:
        """Get mock server list."""
        return [
            {"id": "us-east-1", "name": "US East", "region": "US", "load": 45, "latency": 25, "bandwidth": 1000},
            {"id": "us-west-1", "name": "US West", "region": "US", "load": 30, "latency": 40, "bandwidth": 800},
            {"id": "eu-west-1", "name": "EU West", "region": "EU", "load": 55, "latency": 80, "bandwidth": 900},
            {"id": "eu-central-1", "name": "EU Central", "region": "EU", "load": 40, "latency": 75, "bandwidth": 950},
            {"id": "asia-east-1", "name": "Asia East", "region": "Asia", "load": 35, "latency": 150, "bandwidth": 700},
            {"id": "asia-south-1", "name": "Asia South", "region": "Asia", "load": 25, "latency": 180, "bandwidth": 600},
        ]

    def _connect(self, server_id: Optional[str] = None, privacy_level: str = "STANDARD") -> Dict[str, Any]:
        """Connect to VPN."""
        if self._connected:
            return {"success": False, "message": f"Already connected to {self._current_server}"}

        # Auto-select best server using silver scoring if not specified
        if server_id is None:
            best_server = max(self._servers, key=lambda s: self._silver_score(s))
            server_id = best_server["id"]

        # Find server
        server = next((s for s in self._servers if s["id"] == server_id), None)
        if server is None:
            return {"success": False, "message": f"Server {server_id} not found"}

        self._connected = True
        self._current_server = server_id
        self._privacy_level = privacy_level

        return {
            "success": True,
            "message": f"Connected to {server['name']} ({server_id})",
            "server": server,
            "privacy_level": privacy_level,
        }

    def _disconnect(self) -> Dict[str, Any]:
        """Disconnect from VPN."""
        if not self._connected:
            return {"success": False, "message": "Not connected"}

        server = self._current_server
        self._connected = False
        self._current_server = None

        return {"success": True, "message": f"Disconnected from {server}"}

    def _status(self) -> Dict[str, Any]:
        """Get VPN status."""
        if not self._connected:
            return {
                "connected": False,
                "message": "Not connected to any server",
            }

        server = next((s for s in self._servers if s["id"] == self._current_server), None)
        return {
            "connected": True,
            "server_id": self._current_server,
            "server_name": server["name"] if server else "Unknown",
            "privacy_level": self._privacy_level,
            "latency_ms": server["latency"] if server else 0,
        }

    def _list_servers(self, region: Optional[str] = None) -> Dict[str, Any]:
        """List available servers."""
        servers = self._servers
        if region:
            servers = [s for s in servers if s["region"].lower() == region.lower()]

        # Add silver scores
        for server in servers:
            server["silver_score"] = round(self._silver_score(server), 3)

        return {
            "servers": servers,
            "total": len(servers),
            "filter_region": region,
        }

    def _set_privacy(self, level: str) -> Dict[str, Any]:
        """Set privacy level."""
        valid_levels = ["MINIMAL", "STANDARD", "ENHANCED", "MAXIMUM", "PARANOID"]
        if level not in valid_levels:
            return {"success": False, "message": f"Invalid level. Use one of: {valid_levels}"}

        old_level = self._privacy_level
        self._privacy_level = level

        return {
            "success": True,
            "old_level": old_level,
            "new_level": level,
            "message": f"Privacy level changed from {old_level} to {level}",
        }

    def _routing_info(self) -> Dict[str, Any]:
        """Get routing information."""
        if not self._connected:
            return {"message": "Not connected. Connect to see routing info."}

        server = next((s for s in self._servers if s["id"] == self._current_server), None)
        if not server:
            return {"message": "Server not found"}

        return {
            "server": server["name"],
            "silver_score": round(self._silver_score(server), 4),
            "weights": {
                "latency_weight": round(DELTA_S, 4),
                "bandwidth_weight": round(TAU, 4),
                "load_weight": 1.0,
            },
            "factors": {
                "latency_ms": server["latency"],
                "bandwidth_mbps": server["bandwidth"],
                "load_percent": server["load"],
            },
        }

    def _threat_check(self) -> Dict[str, Any]:
        """Check threat status."""
        return {
            "threat_level": "LOW",
            "score": 0.15,
            "active_protections": [
                "Domain filtering",
                "Traffic analysis",
                "Anomaly detection",
            ],
            "blocked_domains": 0,
            "alerts": [],
        }

    def _explain_silver(self, concept: str) -> Dict[str, Any]:
        """Explain a silver ratio concept."""
        explanations = {
            "silver_ratio": {
                "title": "Silver Ratio (δ_S)",
                "value": f"{DELTA_S:.10f}",
                "formula": "δ_S = 1 + √2",
                "explanation": "The silver ratio is the positive root of x² - 2x - 1 = 0. It has the palindrome property: δ_S = τ² + 1/δ_S where τ = √2.",
            },
            "pell_sequence": {
                "title": "Pell Sequence",
                "values": [0, 1, 2, 5, 12, 29, 70, 169, 408, 985],
                "formula": "P(n) = 2P(n-1) + P(n-2)",
                "explanation": "The Pell sequence converges to the silver ratio: lim(P(n+1)/P(n)) = δ_S. Used for timing intervals.",
            },
            "eta_lambda": {
                "title": "Eta-Lambda Balance",
                "formula": "η² + λ² = 1",
                "values": {"η²": 0.5, "λ²": 0.5},
                "explanation": "Ensures balanced traffic: 50% real data (η²), 50% padding (λ²). Makes traffic analysis extremely difficult.",
            },
            "silver_timing": {
                "title": "Silver Timing",
                "formula": "delay = base × (1 + P(n)/δ_S)",
                "explanation": "Packet timing follows Pell sequence intervals, creating patterns that are deterministic but appear random to observers.",
            },
            "traffic_balance": {
                "title": "Traffic Balance",
                "formula": "real_ratio = η² = 0.5",
                "explanation": "In balanced mode, exactly half of all traffic is real data and half is silver-generated padding. Both are indistinguishable.",
            },
        }

        if concept not in explanations:
            return {"error": f"Unknown concept: {concept}"}

        return explanations[concept]

    def _silver_score(self, server: Dict[str, Any]) -> float:
        """Calculate silver-weighted score for a server."""
        latency_score = 1.0 / (1.0 + server["latency"] / (TAU * 100))
        bandwidth_score = min(server["bandwidth"] / (DELTA_S * 100), 1.0)
        load_score = (100 - server["load"]) / 100.0

        total_weight = DELTA_S + TAU + 1.0
        return (
            latency_score * DELTA_S +
            bandwidth_score * TAU +
            load_score * 1.0
        ) / total_weight

    def get_registry(self) -> ToolRegistry:
        """Get the tool registry."""
        return self.registry
