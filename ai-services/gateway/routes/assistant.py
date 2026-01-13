"""
Chat Assistant Routes

Conversational AI assistant for VPN help and silver ratio education.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from typing import List, Optional, Dict, Any
from enum import Enum

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from assistant import (
    ChatEngine,
    MockBackend,
    OllamaBackend,
    AssistantConfig,
    KnowledgeBase,
    KnowledgeCategory,
    VPNTools,
)

router = APIRouter(prefix="/assistant")


# =============================================================================
# SINGLETONS
# =============================================================================

_chat_engine: Optional[ChatEngine] = None
_knowledge_base: Optional[KnowledgeBase] = None
_vpn_tools: Optional[VPNTools] = None


def get_chat_engine() -> ChatEngine:
    """Get or create chat engine singleton."""
    global _chat_engine
    if _chat_engine is None:
        # Use mock backend by default (Ollama requires local setup)
        config = AssistantConfig(backend="mock")
        _chat_engine = ChatEngine(config=config, backend=MockBackend())
    return _chat_engine


def get_knowledge_base() -> KnowledgeBase:
    """Get or create knowledge base singleton."""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase()
    return _knowledge_base


def get_vpn_tools() -> VPNTools:
    """Get or create VPN tools singleton."""
    global _vpn_tools
    if _vpn_tools is None:
        _vpn_tools = VPNTools()
    return _vpn_tools


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class ChatRequest(BaseModel):
    """Chat message request."""
    message: str = Field(..., min_length=1, max_length=4096)
    conversation_id: Optional[str] = None


class ChatResponse(BaseModel):
    """Chat message response."""
    response: str
    conversation_id: str
    message_id: str
    model_used: str
    tokens_used: int
    generation_time_ms: float
    has_tool_calls: bool = False
    tool_results: Optional[List[dict]] = None


class ConversationInfo(BaseModel):
    """Conversation information."""
    conversation_id: str
    message_count: int
    created_at: str
    updated_at: str
    title: Optional[str] = None


class KnowledgeTopicResponse(BaseModel):
    """Knowledge topic response."""
    title: str
    content: str
    category: str
    keywords: List[str]
    related: List[str]


class KnowledgeSearchResponse(BaseModel):
    """Knowledge search response."""
    query: str
    results: List[dict]
    total_found: int


class ToolExecuteRequest(BaseModel):
    """Tool execution request."""
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolExecuteResponse(BaseModel):
    """Tool execution response."""
    tool_name: str
    success: bool
    result: Any
    error: Optional[str] = None


class PersonalityEnum(str, Enum):
    """Assistant personality options."""
    HELPFUL = "helpful"
    TECHNICAL = "technical"
    FRIENDLY = "friendly"


class ConfigUpdateRequest(BaseModel):
    """Configuration update request."""
    personality: Optional[PersonalityEnum] = None
    temperature: Optional[float] = Field(default=None, ge=0, le=2)
    max_tokens: Optional[int] = Field(default=None, ge=100, le=8192)
    include_knowledge: Optional[bool] = None


# =============================================================================
# ROUTES
# =============================================================================

@router.get("/status")
async def assistant_status():
    """Get assistant service status."""
    engine = get_chat_engine()
    kb = get_knowledge_base()

    return {
        "status": "operational",
        "version": "1.0.0",
        "backend": engine.config.backend,
        "model": engine.config.model_name,
        "knowledge_topics": kb.entry_count,
        "available_tools": len(engine.list_tools()),
        "features": [
            "conversational_ai",
            "vpn_tool_execution",
            "knowledge_base_search",
            "silver_ratio_explanations",
            "context_memory",
        ],
    }


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Send a message to the assistant.

    The assistant can help with:
    - VPN configuration and troubleshooting
    - Privacy settings and recommendations
    - Silver ratio mathematics explanations
    - COINjecture integration questions
    """
    engine = get_chat_engine()

    response = engine.chat(
        user_input=request.message,
        conversation_id=request.conversation_id,
    )

    # Format tool results if any
    tool_results = None
    if response.tool_results:
        tool_results = [tr.to_dict() for tr in response.tool_results]

    return ChatResponse(
        response=response.content,
        conversation_id=response.conversation_id,
        message_id=response.message_id,
        model_used=response.model_used,
        tokens_used=response.tokens_used,
        generation_time_ms=response.generation_time_ms,
        has_tool_calls=response.has_tool_calls,
        tool_results=tool_results,
    )


@router.post("/conversation/new")
async def create_conversation():
    """Create a new conversation."""
    engine = get_chat_engine()
    conversation = engine.create_conversation()

    return {
        "conversation_id": conversation.conversation_id,
        "created_at": conversation.created_at.isoformat(),
        "message": "New conversation created",
    }


@router.get("/conversation/{conversation_id}", response_model=ConversationInfo)
async def get_conversation(conversation_id: str):
    """Get conversation information."""
    engine = get_chat_engine()
    conversation = engine.get_conversation(conversation_id)

    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")

    return ConversationInfo(
        conversation_id=conversation.conversation_id,
        message_count=len(conversation.messages),
        created_at=conversation.created_at.isoformat(),
        updated_at=conversation.updated_at.isoformat(),
        title=conversation.title,
    )


@router.get("/conversation/{conversation_id}/messages")
async def get_conversation_messages(
    conversation_id: str,
    limit: int = Query(default=50, ge=1, le=100),
):
    """Get messages from a conversation."""
    engine = get_chat_engine()
    conversation = engine.get_conversation(conversation_id)

    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")

    messages = conversation.messages[-limit:]
    return {
        "conversation_id": conversation_id,
        "messages": [
            {
                "role": m.role.value,
                "content": m.content,
                "timestamp": m.timestamp.isoformat(),
                "message_id": m.message_id,
            }
            for m in messages
        ],
        "total": len(messages),
    }


@router.delete("/conversation/{conversation_id}")
async def clear_conversation(conversation_id: str):
    """Clear conversation history."""
    engine = get_chat_engine()

    if not engine.clear_conversation(conversation_id):
        raise HTTPException(status_code=404, detail="Conversation not found")

    return {
        "success": True,
        "conversation_id": conversation_id,
        "message": "Conversation cleared",
    }


@router.get("/knowledge/topics")
async def list_knowledge_topics():
    """List all available knowledge topics."""
    kb = get_knowledge_base()
    topics = kb.list_topics()

    # Group by category
    by_category: Dict[str, List[str]] = {}
    for topic in topics:
        entry = kb.get_entry(topic)
        if entry:
            cat = entry.category.value
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(topic)

    return {
        "topics": topics,
        "total": len(topics),
        "by_category": by_category,
    }


@router.get("/knowledge/topic/{topic_name}", response_model=KnowledgeTopicResponse)
async def get_knowledge_topic(topic_name: str):
    """Get a specific knowledge topic."""
    kb = get_knowledge_base()
    entry = kb.get_entry(topic_name)

    if entry is None:
        raise HTTPException(status_code=404, detail=f"Topic '{topic_name}' not found")

    return KnowledgeTopicResponse(
        title=entry.title,
        content=entry.content,
        category=entry.category.value,
        keywords=entry.keywords,
        related=entry.related,
    )


@router.get("/knowledge/search", response_model=KnowledgeSearchResponse)
async def search_knowledge(
    query: str = Query(..., min_length=2),
    max_results: int = Query(default=5, ge=1, le=20),
):
    """Search the knowledge base."""
    kb = get_knowledge_base()
    results = kb.search(query, max_results=max_results)

    formatted_results = [
        {
            "title": entry.title,
            "category": entry.category.value,
            "relevance_score": score,
            "preview": entry.content[:200] + "..." if len(entry.content) > 200 else entry.content,
        }
        for entry, score in results
    ]

    return KnowledgeSearchResponse(
        query=query,
        results=formatted_results,
        total_found=len(results),
    )


@router.get("/tools")
async def list_tools():
    """List available VPN tools the assistant can use."""
    tools = get_vpn_tools()
    registry = tools.get_registry()

    tool_list = []
    for name in registry.list_tools():
        tool = registry.get(name)
        if tool:
            tool_list.append({
                "name": tool.name,
                "description": tool.description,
                "parameters": [
                    {
                        "name": p.name,
                        "type": p.type,
                        "description": p.description,
                        "required": p.required,
                    }
                    for p in tool.parameters
                ],
            })

    return {
        "tools": tool_list,
        "total": len(tool_list),
    }


@router.post("/tools/execute", response_model=ToolExecuteResponse)
async def execute_tool(request: ToolExecuteRequest):
    """
    Execute a VPN tool directly.

    Available tools:
    - vpn_connect: Connect to a server
    - vpn_disconnect: Disconnect from VPN
    - vpn_status: Get connection status
    - vpn_list_servers: List available servers
    - vpn_set_privacy: Set privacy level
    - vpn_routing_info: Get routing information
    - vpn_threat_check: Check threat status
    - explain_silver: Explain silver ratio concepts
    """
    tools = get_vpn_tools()
    registry = tools.get_registry()

    tool = registry.get(request.tool_name)
    if tool is None:
        raise HTTPException(
            status_code=404,
            detail=f"Tool '{request.tool_name}' not found",
        )

    try:
        result = registry.execute(request.tool_name, **request.arguments)
        return ToolExecuteResponse(
            tool_name=request.tool_name,
            success=True,
            result=result,
        )
    except Exception as e:
        return ToolExecuteResponse(
            tool_name=request.tool_name,
            success=False,
            result=None,
            error=str(e),
        )


@router.get("/config")
async def get_config():
    """Get current assistant configuration."""
    engine = get_chat_engine()
    config = engine.config

    return {
        "model_name": config.model_name,
        "backend": config.backend,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "personality": config.personality,
        "include_knowledge_base": config.include_knowledge_base,
        "enable_tools": config.enable_tools,
    }


@router.post("/config")
async def update_config(request: ConfigUpdateRequest):
    """Update assistant configuration."""
    engine = get_chat_engine()

    if request.personality:
        engine.config.personality = request.personality.value

    if request.temperature is not None:
        engine.config.temperature = request.temperature

    if request.max_tokens is not None:
        engine.config.max_tokens = request.max_tokens

    if request.include_knowledge is not None:
        engine.config.include_knowledge_base = request.include_knowledge

    return {
        "success": True,
        "updated_config": {
            "personality": engine.config.personality,
            "temperature": engine.config.temperature,
            "max_tokens": engine.config.max_tokens,
            "include_knowledge_base": engine.config.include_knowledge_base,
        },
    }


@router.get("/quick-help")
async def quick_help():
    """Get quick help topics."""
    return {
        "topics": [
            {
                "question": "How do I connect to the VPN?",
                "answer": "Use the chat to say 'connect me' or execute the vpn_connect tool. The AI router will automatically select the best server.",
            },
            {
                "question": "What privacy level should I use?",
                "answer": "STANDARD is good for everyday use. Use ENHANCED for sensitive activities, MAXIMUM for high-security needs, or PARANOID in hostile networks.",
            },
            {
                "question": "What is the silver ratio?",
                "answer": "δ_S = 1 + √2 ≈ 2.414. It's the mathematical foundation of SilverVPN, used for timing, padding, and load balancing.",
            },
            {
                "question": "Why is my connection slow?",
                "answer": "Try a closer server, reduce privacy level (less overhead), or let the AI router find a better path.",
            },
            {
                "question": "What is η² + λ² = 1?",
                "answer": "The silver balance equation. In balanced mode, 50% is real data (η²) and 50% is padding (λ²), making traffic analysis impossible.",
            },
        ],
        "hint": "Ask the assistant anything about VPN, privacy, or silver ratio mathematics!",
    }
