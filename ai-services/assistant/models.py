"""
Chat Assistant Models

Data structures for conversations, messages, and assistant configuration.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


class MessageRole(Enum):
    """Role of a message sender."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class Message:
    """A single message in a conversation."""
    role: MessageRole
    content: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Optional metadata
    tool_calls: Optional[List["ToolCall"]] = None
    tool_results: Optional[List["ToolResult"]] = None
    tokens_used: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API calls."""
        result = {
            "role": self.role.value,
            "content": self.content,
        }
        if self.tool_calls:
            result["tool_calls"] = [tc.to_dict() for tc in self.tool_calls]
        return result

    @classmethod
    def system(cls, content: str) -> "Message":
        """Create a system message."""
        return cls(role=MessageRole.SYSTEM, content=content)

    @classmethod
    def user(cls, content: str) -> "Message":
        """Create a user message."""
        return cls(role=MessageRole.USER, content=content)

    @classmethod
    def assistant(cls, content: str, tool_calls: Optional[List["ToolCall"]] = None) -> "Message":
        """Create an assistant message."""
        return cls(role=MessageRole.ASSISTANT, content=content, tool_calls=tool_calls)


@dataclass
class ToolCall:
    """A tool/function call requested by the assistant."""
    tool_id: str
    tool_name: str
    arguments: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.tool_id,
            "name": self.tool_name,
            "arguments": self.arguments,
        }


@dataclass
class ToolResult:
    """Result of executing a tool."""
    tool_id: str
    tool_name: str
    result: Any
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "result": str(self.result),
            "success": self.success,
            "error": self.error,
        }


@dataclass
class Conversation:
    """A conversation with message history."""
    conversation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    messages: List[Message] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # Metadata
    title: Optional[str] = None
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Token tracking
    total_tokens: int = 0

    def add_message(self, message: Message) -> None:
        """Add a message to the conversation."""
        self.messages.append(message)
        self.updated_at = datetime.utcnow()
        self.total_tokens += message.tokens_used

    def get_messages_for_context(self, max_messages: int = 20) -> List[Message]:
        """Get recent messages for context window."""
        # Always include system message if present
        system_msgs = [m for m in self.messages if m.role == MessageRole.SYSTEM]
        other_msgs = [m for m in self.messages if m.role != MessageRole.SYSTEM]

        # Take most recent messages
        recent = other_msgs[-(max_messages - len(system_msgs)):]

        return system_msgs + recent

    def to_api_messages(self, max_messages: int = 20) -> List[Dict[str, Any]]:
        """Convert to API message format."""
        messages = self.get_messages_for_context(max_messages)
        return [m.to_dict() for m in messages]

    def clear(self) -> None:
        """Clear conversation history (keep system message)."""
        system_msgs = [m for m in self.messages if m.role == MessageRole.SYSTEM]
        self.messages = system_msgs
        self.total_tokens = sum(m.tokens_used for m in self.messages)


@dataclass
class AssistantConfig:
    """Configuration for the chat assistant."""
    # Model settings
    model_name: str = "llama3.2"
    temperature: float = 0.7
    max_tokens: int = 2048
    top_p: float = 0.9

    # Backend settings
    backend: str = "ollama"  # "ollama", "openai", "anthropic", "mock"
    api_base_url: str = "http://localhost:11434"
    api_key: Optional[str] = None

    # Context settings
    max_context_messages: int = 20
    include_knowledge_base: bool = True

    # Personality
    system_prompt: str = ""
    personality: str = "helpful"  # "helpful", "technical", "friendly"

    # Features
    enable_tools: bool = True
    enable_streaming: bool = False

    def get_system_prompt(self) -> str:
        """Get the full system prompt."""
        if self.system_prompt:
            return self.system_prompt

        base_prompt = """You are SilverVPN Assistant, an AI helper for SilverVPN - a privacy-focused VPN built on silver ratio mathematics from the COINjecture blockchain project.

You can help users with:
1. VPN Configuration - Setting up connections, choosing servers, privacy settings
2. Troubleshooting - Diagnosing connection issues, performance problems
3. Privacy & Security - Understanding privacy levels, threat detection, traffic obfuscation
4. Silver Ratio Concepts - Explaining the mathematical foundations (δ_S = 1 + √2, Pell sequence, η² + λ² = 1)
5. COINjecture Integration - How the VPN connects to the P2P network

Key Silver Constants:
- η (eta) = 1/√2 ≈ 0.707 (unit component)
- τ (tau) = √2 ≈ 1.414 (fundamental ratio)
- δ_S (delta_S) = 1 + √2 ≈ 2.414 (silver ratio)
- Balanced traffic: η² + λ² = 1 (50% real, 50% padding)

Be concise but thorough. Use technical terms when appropriate but explain them for non-technical users."""

        if self.personality == "technical":
            base_prompt += "\n\nBe precise and technical. Include mathematical details when relevant."
        elif self.personality == "friendly":
            base_prompt += "\n\nBe warm and encouraging. Use simple language and analogies."

        return base_prompt


@dataclass
class AssistantResponse:
    """Response from the assistant."""
    content: str
    conversation_id: str
    message_id: str

    # Metadata
    model_used: str = ""
    tokens_used: int = 0
    generation_time_ms: float = 0.0

    # Tool handling
    tool_calls: Optional[List[ToolCall]] = None
    tool_results: Optional[List[ToolResult]] = None

    # Status
    finished: bool = True
    error: Optional[str] = None

    @property
    def has_tool_calls(self) -> bool:
        """Check if response includes tool calls."""
        return self.tool_calls is not None and len(self.tool_calls) > 0
