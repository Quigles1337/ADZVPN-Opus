"""
SilverVPN Chat Assistant

AI-powered conversational assistant for VPN configuration,
troubleshooting, and COINjecture/silver ratio education.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

from .models import (
    MessageRole,
    Message,
    Conversation,
    AssistantConfig,
    ToolCall,
    ToolResult,
    AssistantResponse,
)
from .knowledge_base import (
    KnowledgeBase,
    KnowledgeCategory,
    KnowledgeEntry,
)
from .context_manager import (
    ContextManager,
    ConversationMemory,
)
from .tools import (
    AssistantTool,
    ToolRegistry,
    VPNTools,
)
from .chat_engine import (
    ChatEngine,
    OllamaBackend,
    MockBackend,
)

__all__ = [
    # Models
    "MessageRole",
    "Message",
    "Conversation",
    "AssistantConfig",
    "ToolCall",
    "ToolResult",
    "AssistantResponse",
    # Knowledge
    "KnowledgeBase",
    "KnowledgeCategory",
    "KnowledgeEntry",
    # Context
    "ContextManager",
    "ConversationMemory",
    # Tools
    "AssistantTool",
    "ToolRegistry",
    "VPNTools",
    # Engine
    "ChatEngine",
    "OllamaBackend",
    "MockBackend",
]
