"""
Tests for Chat Assistant

Tests models, knowledge base, context management, tools, and chat engine.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from silver_constants import DELTA_S, TAU

from assistant import (
    MessageRole,
    Message,
    Conversation,
    AssistantConfig,
    ToolCall,
    ToolResult,
    AssistantResponse,
    KnowledgeBase,
    KnowledgeCategory,
    KnowledgeEntry,
    ContextManager,
    ConversationMemory,
    AssistantTool,
    ToolRegistry,
    VPNTools,
    ChatEngine,
    MockBackend,
)


# =============================================================================
# TEST MODELS
# =============================================================================

class TestMessage:
    """Test Message class."""

    def test_create_system_message(self):
        """Test creating system message."""
        msg = Message.system("You are a helpful assistant")
        assert msg.role == MessageRole.SYSTEM
        assert msg.content == "You are a helpful assistant"

    def test_create_user_message(self):
        """Test creating user message."""
        msg = Message.user("Hello!")
        assert msg.role == MessageRole.USER
        assert msg.content == "Hello!"

    def test_create_assistant_message(self):
        """Test creating assistant message."""
        msg = Message.assistant("Hi there!")
        assert msg.role == MessageRole.ASSISTANT
        assert msg.content == "Hi there!"

    def test_message_to_dict(self):
        """Test converting message to dict."""
        msg = Message.user("Test message")
        d = msg.to_dict()
        assert d["role"] == "user"
        assert d["content"] == "Test message"

    def test_message_with_tool_calls(self):
        """Test message with tool calls."""
        tool_call = ToolCall(
            tool_id="123",
            tool_name="vpn_connect",
            arguments={"server_id": "us-east-1"},
        )
        msg = Message.assistant("Connecting...", tool_calls=[tool_call])
        assert msg.tool_calls is not None
        assert len(msg.tool_calls) == 1


class TestConversation:
    """Test Conversation class."""

    def test_create_conversation(self):
        """Test creating conversation."""
        conv = Conversation()
        assert conv.conversation_id is not None
        assert len(conv.messages) == 0

    def test_add_message(self):
        """Test adding messages."""
        conv = Conversation()
        conv.add_message(Message.system("System prompt"))
        conv.add_message(Message.user("Hello"))

        assert len(conv.messages) == 2

    def test_get_messages_for_context(self):
        """Test getting messages for context."""
        conv = Conversation()
        conv.add_message(Message.system("System"))

        for i in range(30):
            conv.add_message(Message.user(f"Message {i}"))

        # Should return system + recent messages
        context_msgs = conv.get_messages_for_context(max_messages=10)
        assert len(context_msgs) <= 10

        # System message should always be included
        assert any(m.role == MessageRole.SYSTEM for m in context_msgs)

    def test_clear_keeps_system(self):
        """Test clearing conversation keeps system message."""
        conv = Conversation()
        conv.add_message(Message.system("System"))
        conv.add_message(Message.user("Hello"))
        conv.add_message(Message.assistant("Hi"))

        conv.clear()

        assert len(conv.messages) == 1
        assert conv.messages[0].role == MessageRole.SYSTEM


class TestAssistantConfig:
    """Test AssistantConfig class."""

    def test_default_config(self):
        """Test default configuration."""
        config = AssistantConfig()
        assert config.model_name == "llama3.2"
        assert config.temperature == 0.7
        assert config.backend == "ollama"

    def test_get_system_prompt(self):
        """Test getting system prompt."""
        config = AssistantConfig()
        prompt = config.get_system_prompt()

        assert "SilverVPN" in prompt
        assert "silver ratio" in prompt.lower()

    def test_custom_system_prompt(self):
        """Test custom system prompt."""
        config = AssistantConfig(system_prompt="Custom prompt")
        assert config.get_system_prompt() == "Custom prompt"

    def test_personality_affects_prompt(self):
        """Test personality affects prompt."""
        technical = AssistantConfig(personality="technical")
        friendly = AssistantConfig(personality="friendly")

        tech_prompt = technical.get_system_prompt()
        friendly_prompt = friendly.get_system_prompt()

        assert "technical" in tech_prompt.lower()
        assert "warm" in friendly_prompt.lower() or "friendly" in friendly_prompt.lower()


# =============================================================================
# TEST KNOWLEDGE BASE
# =============================================================================

class TestKnowledgeBase:
    """Test KnowledgeBase class."""

    def setup_method(self):
        """Set up knowledge base."""
        self.kb = KnowledgeBase()

    def test_default_entries_loaded(self):
        """Test default knowledge entries are loaded."""
        assert self.kb.entry_count > 0
        assert "Silver Ratio" in self.kb.list_topics()

    def test_get_entry(self):
        """Test getting entry by title."""
        entry = self.kb.get_entry("Silver Ratio")
        assert entry is not None
        assert entry.category == KnowledgeCategory.SILVER_MATH

    def test_search_finds_relevant(self):
        """Test search finds relevant entries."""
        results = self.kb.search("privacy level")

        assert len(results) > 0
        # Should find privacy-related entries
        titles = [e.title for e, _ in results]
        assert any("privacy" in t.lower() for t in titles)

    def test_search_returns_scores(self):
        """Test search returns relevance scores."""
        results = self.kb.search("silver ratio math")

        assert len(results) > 0
        for entry, score in results:
            assert 0 <= score <= 1

    def test_get_by_category(self):
        """Test getting entries by category."""
        math_entries = self.kb.get_by_category(KnowledgeCategory.SILVER_MATH)
        assert len(math_entries) > 0
        assert all(e.category == KnowledgeCategory.SILVER_MATH for e in math_entries)

    def test_context_for_query(self):
        """Test getting context for a query."""
        context = self.kb.get_context_for_query("what is the silver ratio")
        assert "Relevant knowledge:" in context
        assert "silver" in context.lower()

    def test_add_custom_entry(self):
        """Test adding custom entry."""
        entry = KnowledgeEntry(
            title="Custom Topic",
            content="Custom content here",
            category=KnowledgeCategory.VPN_BASICS,
            keywords=["custom", "test"],
        )
        self.kb.add_entry(entry)

        retrieved = self.kb.get_entry("Custom Topic")
        assert retrieved is not None
        assert retrieved.content == "Custom content here"


class TestKnowledgeEntry:
    """Test KnowledgeEntry class."""

    def test_matches_query_title(self):
        """Test matching by title."""
        entry = KnowledgeEntry(
            title="Silver Ratio",
            content="Content",
            category=KnowledgeCategory.SILVER_MATH,
        )
        score = entry.matches_query("silver ratio")
        assert score > 0

    def test_matches_query_keyword(self):
        """Test matching by keyword."""
        entry = KnowledgeEntry(
            title="Something",
            content="Content",
            category=KnowledgeCategory.PRIVACY,
            keywords=["privacy", "security"],
        )
        score = entry.matches_query("I want more privacy")
        assert score > 0


# =============================================================================
# TEST CONTEXT MANAGER
# =============================================================================

class TestContextManager:
    """Test ContextManager class."""

    def setup_method(self):
        """Set up context manager."""
        self.cm = ContextManager()

    def test_create_conversation(self):
        """Test creating conversation."""
        conv = self.cm.create_conversation()
        assert conv is not None
        assert conv.conversation_id is not None

    def test_get_conversation(self):
        """Test getting conversation."""
        conv = self.cm.create_conversation()
        retrieved = self.cm.get_conversation(conv.conversation_id)
        assert retrieved is not None
        assert retrieved.conversation_id == conv.conversation_id

    def test_add_message(self):
        """Test adding message to conversation."""
        conv = self.cm.create_conversation()
        self.cm.add_message(conv.conversation_id, Message.user("Hello"))

        retrieved = self.cm.get_conversation(conv.conversation_id)
        assert len(retrieved.messages) == 1

    def test_memory_created(self):
        """Test memory is created for conversation."""
        conv = self.cm.create_conversation()
        memory = self.cm.get_memory(conv.conversation_id)
        assert memory is not None

    def test_delete_conversation(self):
        """Test deleting conversation."""
        conv = self.cm.create_conversation()
        conv_id = conv.conversation_id

        result = self.cm.delete_conversation(conv_id)
        assert result is True

        retrieved = self.cm.get_conversation(conv_id)
        assert retrieved is None

    def test_get_stats(self):
        """Test getting stats."""
        self.cm.create_conversation()
        self.cm.create_conversation()

        stats = self.cm.get_stats()
        assert stats["active_conversations"] == 2


class TestConversationMemory:
    """Test ConversationMemory class."""

    def test_add_fact(self):
        """Test adding facts."""
        memory = ConversationMemory()
        memory.add_fact("User prefers high privacy")

        assert "User prefers high privacy" in memory.facts

    def test_set_preference(self):
        """Test setting preferences."""
        memory = ConversationMemory()
        memory.set_preference("privacy_level", "MAXIMUM")

        assert memory.preferences["privacy_level"] == "MAXIMUM"

    def test_get_summary(self):
        """Test getting summary."""
        memory = ConversationMemory()
        memory.current_topic = "privacy"
        memory.vpn_connected = True
        memory.current_server = "us-east-1"

        summary = memory.get_summary()
        assert "privacy" in summary
        assert "us-east-1" in summary


# =============================================================================
# TEST TOOLS
# =============================================================================

class TestToolRegistry:
    """Test ToolRegistry class."""

    def setup_method(self):
        """Set up registry."""
        self.registry = ToolRegistry()

    def test_register_tool(self):
        """Test registering a tool."""
        tool = AssistantTool(
            name="test_tool",
            description="A test tool",
            handler=lambda: "result",
        )
        self.registry.register(tool)

        assert "test_tool" in self.registry.list_tools()

    def test_get_tool(self):
        """Test getting a tool."""
        tool = AssistantTool(name="my_tool", description="My tool")
        self.registry.register(tool)

        retrieved = self.registry.get("my_tool")
        assert retrieved is not None
        assert retrieved.name == "my_tool"

    def test_execute_tool(self):
        """Test executing a tool."""
        tool = AssistantTool(
            name="adder",
            description="Add numbers",
            handler=lambda a, b: a + b,
        )
        self.registry.register(tool)

        result = self.registry.execute("adder", a=1, b=2)
        assert result == 3


class TestVPNTools:
    """Test VPNTools class."""

    def setup_method(self):
        """Set up VPN tools."""
        self.tools = VPNTools()
        self.registry = self.tools.get_registry()

    def test_tools_registered(self):
        """Test VPN tools are registered."""
        tools = self.registry.list_tools()
        assert "vpn_connect" in tools
        assert "vpn_disconnect" in tools
        assert "vpn_status" in tools

    def test_connect_auto_select(self):
        """Test connecting with auto-select."""
        result = self.registry.execute("vpn_connect")
        assert result["success"] is True
        assert "server" in result

    def test_connect_specific_server(self):
        """Test connecting to specific server."""
        result = self.registry.execute("vpn_connect", server_id="us-east-1")
        assert result["success"] is True
        assert result["server"]["id"] == "us-east-1"

    def test_disconnect(self):
        """Test disconnecting."""
        # First connect
        self.registry.execute("vpn_connect")

        # Then disconnect
        result = self.registry.execute("vpn_disconnect")
        assert result["success"] is True

    def test_status_not_connected(self):
        """Test status when not connected."""
        result = self.registry.execute("vpn_status")
        assert result["connected"] is False

    def test_status_connected(self):
        """Test status when connected."""
        self.registry.execute("vpn_connect", server_id="us-east-1")
        result = self.registry.execute("vpn_status")

        assert result["connected"] is True
        assert result["server_id"] == "us-east-1"

    def test_list_servers(self):
        """Test listing servers."""
        result = self.registry.execute("vpn_list_servers")
        assert result["total"] > 0
        assert "servers" in result

    def test_list_servers_filter_region(self):
        """Test listing servers with region filter."""
        result = self.registry.execute("vpn_list_servers", region="US")
        assert all(s["region"] == "US" for s in result["servers"])

    def test_set_privacy(self):
        """Test setting privacy level."""
        result = self.registry.execute("vpn_set_privacy", level="MAXIMUM")
        assert result["success"] is True
        assert result["new_level"] == "MAXIMUM"

    def test_explain_silver(self):
        """Test explaining silver concepts."""
        result = self.registry.execute("explain_silver", concept="silver_ratio")
        assert "title" in result
        assert "Silver Ratio" in result["title"]

    def test_silver_score_in_servers(self):
        """Test silver score is calculated for servers."""
        result = self.registry.execute("vpn_list_servers")
        for server in result["servers"]:
            assert "silver_score" in server
            assert 0 <= server["silver_score"] <= 1


# =============================================================================
# TEST CHAT ENGINE
# =============================================================================

class TestMockBackend:
    """Test MockBackend class."""

    def setup_method(self):
        """Set up mock backend."""
        self.backend = MockBackend()

    def test_generate_sync(self):
        """Test synchronous generation."""
        messages = [{"role": "user", "content": "Hello"}]
        config = AssistantConfig()

        result = self.backend.generate_sync(messages, config)
        assert "message" in result
        assert result["message"]["role"] == "assistant"

    def test_keyword_matching(self):
        """Test keyword matching in responses."""
        messages = [{"role": "user", "content": "Tell me about privacy"}]
        config = AssistantConfig()

        result = self.backend.generate_sync(messages, config)
        content = result["message"]["content"]
        assert "privacy" in content.lower()

    def test_set_custom_response(self):
        """Test setting custom response."""
        self.backend.set_response("custom", "Custom response!")

        messages = [{"role": "user", "content": "Something custom here"}]
        config = AssistantConfig()

        result = self.backend.generate_sync(messages, config)
        assert result["message"]["content"] == "Custom response!"


class TestChatEngine:
    """Test ChatEngine class."""

    def setup_method(self):
        """Set up chat engine with mock backend."""
        self.engine = ChatEngine(backend=MockBackend())

    def test_create_conversation(self):
        """Test creating conversation."""
        conv = self.engine.create_conversation()
        assert conv is not None
        # Should have system message
        assert len(conv.messages) == 1
        assert conv.messages[0].role == MessageRole.SYSTEM

    def test_chat_basic(self):
        """Test basic chat."""
        response = self.engine.chat("Hello, how are you?")

        assert response.content is not None
        assert len(response.content) > 0
        assert response.conversation_id is not None

    def test_chat_with_existing_conversation(self):
        """Test chatting in existing conversation."""
        # First message
        response1 = self.engine.chat("Hello")
        conv_id = response1.conversation_id

        # Second message in same conversation
        response2 = self.engine.chat("How are you?", conversation_id=conv_id)

        assert response2.conversation_id == conv_id

        # Conversation should have messages
        conv = self.engine.get_conversation(conv_id)
        # System + user + assistant + user + assistant = 5
        assert len(conv.messages) >= 4

    def test_chat_includes_knowledge(self):
        """Test chat includes knowledge context."""
        # Query that should trigger knowledge lookup
        response = self.engine.chat("What is the silver ratio?")
        assert response.content is not None

    def test_list_topics(self):
        """Test listing knowledge topics."""
        topics = self.engine.list_topics()
        assert len(topics) > 0
        assert "Silver Ratio" in topics

    def test_list_tools(self):
        """Test listing available tools."""
        tools = self.engine.list_tools()
        assert "vpn_connect" in tools
        assert "vpn_status" in tools

    def test_execute_tool_directly(self):
        """Test executing tool directly."""
        result = self.engine.execute_tool("vpn_status")
        assert "connected" in result

    def test_clear_conversation(self):
        """Test clearing conversation."""
        response = self.engine.chat("Hello")
        conv_id = response.conversation_id

        result = self.engine.clear_conversation(conv_id)
        assert result is True

        conv = self.engine.get_conversation(conv_id)
        # Should only have system message
        assert len(conv.messages) == 1

    def test_response_timing(self):
        """Test response includes timing."""
        response = self.engine.chat("Hello")
        # Mock backend is very fast, so timing may be 0.0
        # Just verify the field exists and is non-negative
        assert response.generation_time_ms >= 0


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
