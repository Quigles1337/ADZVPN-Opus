"""
Context Manager

Manages conversation context and memory for the chat assistant.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque

from .models import Message, Conversation, MessageRole


@dataclass
class ConversationMemory:
    """
    Memory storage for a conversation.

    Tracks important facts, user preferences, and session state.
    """
    # Extracted facts from conversation
    facts: List[str] = field(default_factory=list)

    # User preferences learned during session
    preferences: Dict[str, Any] = field(default_factory=dict)

    # Current topic/context
    current_topic: Optional[str] = None

    # Recent entities mentioned
    entities: List[str] = field(default_factory=list)

    # Session state
    vpn_connected: bool = False
    current_server: Optional[str] = None
    privacy_level: str = "STANDARD"
    last_action: Optional[str] = None

    def add_fact(self, fact: str) -> None:
        """Add a fact to memory."""
        if fact not in self.facts:
            self.facts.append(fact)
            # Keep only recent facts
            if len(self.facts) > 20:
                self.facts.pop(0)

    def set_preference(self, key: str, value: Any) -> None:
        """Set a user preference."""
        self.preferences[key] = value

    def add_entity(self, entity: str) -> None:
        """Add a mentioned entity."""
        if entity not in self.entities:
            self.entities.append(entity)
            if len(self.entities) > 10:
                self.entities.pop(0)

    def get_summary(self) -> str:
        """Get a summary of the current memory state."""
        parts = []

        if self.current_topic:
            parts.append(f"Current topic: {self.current_topic}")

        if self.vpn_connected:
            parts.append(f"VPN connected to: {self.current_server}")
            parts.append(f"Privacy level: {self.privacy_level}")

        if self.facts:
            parts.append(f"Known facts: {', '.join(self.facts[-5:])}")

        if self.preferences:
            prefs = [f"{k}={v}" for k, v in list(self.preferences.items())[:5]]
            parts.append(f"User preferences: {', '.join(prefs)}")

        return "; ".join(parts) if parts else "No context stored"


class ContextManager:
    """
    Manages context across conversations.

    Handles:
    - Conversation storage and retrieval
    - Memory extraction and summarization
    - Context window management
    - Multi-conversation tracking
    """

    def __init__(self, max_conversations: int = 100):
        """
        Initialize context manager.

        Args:
            max_conversations: Maximum conversations to keep in memory
        """
        self._conversations: Dict[str, Conversation] = {}
        self._memories: Dict[str, ConversationMemory] = {}
        self._max_conversations = max_conversations
        self._conversation_order: deque = deque(maxlen=max_conversations)

    def create_conversation(self, user_id: Optional[str] = None) -> Conversation:
        """Create a new conversation."""
        conversation = Conversation(user_id=user_id)
        self._conversations[conversation.conversation_id] = conversation
        self._memories[conversation.conversation_id] = ConversationMemory()
        self._conversation_order.append(conversation.conversation_id)

        # Prune old conversations if needed
        self._prune_old_conversations()

        return conversation

    def get_conversation(self, conversation_id: str) -> Optional[Conversation]:
        """Get a conversation by ID."""
        return self._conversations.get(conversation_id)

    def get_memory(self, conversation_id: str) -> Optional[ConversationMemory]:
        """Get memory for a conversation."""
        return self._memories.get(conversation_id)

    def add_message(
        self,
        conversation_id: str,
        message: Message,
    ) -> None:
        """Add a message to a conversation."""
        conversation = self._conversations.get(conversation_id)
        if conversation:
            conversation.add_message(message)
            self._extract_context(conversation_id, message)

    def _extract_context(self, conversation_id: str, message: Message) -> None:
        """Extract context from a message and update memory."""
        memory = self._memories.get(conversation_id)
        if not memory:
            return

        content_lower = message.content.lower()

        # Topic detection
        if "privacy" in content_lower or "obfuscation" in content_lower:
            memory.current_topic = "privacy"
        elif "connect" in content_lower or "server" in content_lower:
            memory.current_topic = "connection"
        elif "silver" in content_lower or "ratio" in content_lower or "pell" in content_lower:
            memory.current_topic = "silver_math"
        elif "threat" in content_lower or "security" in content_lower:
            memory.current_topic = "security"
        elif "help" in content_lower or "how" in content_lower:
            memory.current_topic = "help"

        # Entity extraction (simple keyword-based)
        keywords = ["vpn", "server", "privacy", "security", "coinjecture", "silver ratio"]
        for keyword in keywords:
            if keyword in content_lower:
                memory.add_entity(keyword)

        # VPN state tracking (from assistant responses)
        if message.role == MessageRole.ASSISTANT:
            if "connected to" in content_lower:
                memory.vpn_connected = True
            elif "disconnected" in content_lower:
                memory.vpn_connected = False

    def get_context_string(
        self,
        conversation_id: str,
        include_memory: bool = True,
    ) -> str:
        """
        Get context string for prompting.

        Includes conversation summary and memory state.
        """
        parts = []

        conversation = self._conversations.get(conversation_id)
        memory = self._memories.get(conversation_id)

        if conversation and conversation.messages:
            msg_count = len([m for m in conversation.messages if m.role != MessageRole.SYSTEM])
            parts.append(f"Conversation has {msg_count} messages")

        if include_memory and memory:
            summary = memory.get_summary()
            if summary != "No context stored":
                parts.append(f"Context: {summary}")

        return ". ".join(parts)

    def clear_conversation(self, conversation_id: str) -> bool:
        """Clear a conversation's history (keep memory)."""
        conversation = self._conversations.get(conversation_id)
        if conversation:
            conversation.clear()
            return True
        return False

    def delete_conversation(self, conversation_id: str) -> bool:
        """Delete a conversation entirely."""
        if conversation_id in self._conversations:
            del self._conversations[conversation_id]
            if conversation_id in self._memories:
                del self._memories[conversation_id]
            return True
        return False

    def get_user_conversations(self, user_id: str) -> List[Conversation]:
        """Get all conversations for a user."""
        return [
            c for c in self._conversations.values()
            if c.user_id == user_id
        ]

    def _prune_old_conversations(self) -> None:
        """Remove old conversations to stay under limit."""
        while len(self._conversations) > self._max_conversations:
            if self._conversation_order:
                oldest_id = self._conversation_order.popleft()
                self.delete_conversation(oldest_id)

    def get_stats(self) -> Dict[str, Any]:
        """Get context manager statistics."""
        total_messages = sum(
            len(c.messages) for c in self._conversations.values()
        )
        return {
            "active_conversations": len(self._conversations),
            "total_messages": total_messages,
            "max_conversations": self._max_conversations,
        }


class SlidingWindowContext:
    """
    Sliding window for managing context tokens.

    Ensures we don't exceed model context limits.
    """

    def __init__(self, max_tokens: int = 4096, tokens_per_message: int = 50):
        """
        Initialize sliding window.

        Args:
            max_tokens: Maximum tokens in context
            tokens_per_message: Estimated tokens per message
        """
        self.max_tokens = max_tokens
        self.tokens_per_message = tokens_per_message

    def fit_messages(
        self,
        messages: List[Message],
        system_tokens: int = 500,
        response_tokens: int = 500,
    ) -> List[Message]:
        """
        Fit messages into context window.

        Always keeps system message and most recent messages.
        """
        available_tokens = self.max_tokens - system_tokens - response_tokens

        # Separate system messages
        system_msgs = [m for m in messages if m.role == MessageRole.SYSTEM]
        other_msgs = [m for m in messages if m.role != MessageRole.SYSTEM]

        # Estimate tokens used by system messages
        system_used = len(system_msgs) * self.tokens_per_message

        # Calculate how many messages we can fit
        remaining = available_tokens - system_used
        max_messages = max(1, remaining // self.tokens_per_message)

        # Take most recent messages
        fitted = other_msgs[-max_messages:]

        return system_msgs + fitted

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text."""
        # Rough estimate: ~4 characters per token
        return len(text) // 4
