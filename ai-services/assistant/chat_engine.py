"""
Chat Engine

Core chat logic with LLM backend integration (Ollama, OpenAI, etc.)

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import json
import time
import uuid
import httpx
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Dict, List, Optional
from dataclasses import dataclass

from .models import (
    Message,
    MessageRole,
    Conversation,
    AssistantConfig,
    AssistantResponse,
    ToolCall,
    ToolResult,
)
from .knowledge_base import KnowledgeBase
from .context_manager import ContextManager, SlidingWindowContext
from .tools import ToolRegistry, VPNTools


class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    @abstractmethod
    async def generate(
        self,
        messages: List[Dict[str, Any]],
        config: AssistantConfig,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate a response from the LLM."""
        pass

    @abstractmethod
    def generate_sync(
        self,
        messages: List[Dict[str, Any]],
        config: AssistantConfig,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Synchronous version of generate."""
        pass


class OllamaBackend(LLMBackend):
    """
    Ollama LLM backend.

    Connects to a local Ollama instance for inference.
    """

    def __init__(self, base_url: str = "http://localhost:11434"):
        """
        Initialize Ollama backend.

        Args:
            base_url: Ollama API base URL
        """
        self.base_url = base_url.rstrip("/")
        self.chat_endpoint = f"{self.base_url}/api/chat"

    async def generate(
        self,
        messages: List[Dict[str, Any]],
        config: AssistantConfig,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate response using Ollama."""
        payload = {
            "model": config.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": config.temperature,
                "top_p": config.top_p,
                "num_predict": config.max_tokens,
            },
        }

        if tools:
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                response = await client.post(self.chat_endpoint, json=payload)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                return {
                    "error": str(e),
                    "message": {"role": "assistant", "content": "Sorry, I couldn't connect to the AI service."},
                }

    def generate_sync(
        self,
        messages: List[Dict[str, Any]],
        config: AssistantConfig,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Synchronous version of generate."""
        payload = {
            "model": config.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": config.temperature,
                "top_p": config.top_p,
                "num_predict": config.max_tokens,
            },
        }

        if tools:
            payload["tools"] = tools

        try:
            with httpx.Client(timeout=120.0) as client:
                response = client.post(self.chat_endpoint, json=payload)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            return {
                "error": str(e),
                "message": {"role": "assistant", "content": "Sorry, I couldn't connect to the AI service."},
            }

    def is_available(self) -> bool:
        """Check if Ollama is available."""
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False


class MockBackend(LLMBackend):
    """
    Mock backend for testing.

    Returns predefined responses without calling an actual LLM.
    """

    def __init__(self):
        """Initialize mock backend."""
        self._responses: Dict[str, str] = {
            "default": "I'm the SilverVPN assistant. I can help you with VPN configuration, privacy settings, and explain silver ratio mathematics.",
            "connect": "I'll help you connect to a VPN server. Use the vpn_connect command or let me auto-select the best server.",
            "privacy": "SilverVPN offers five privacy levels: MINIMAL, STANDARD, ENHANCED, MAXIMUM, and PARANOID. Higher levels provide more protection.",
            "silver": "The silver ratio (δ_S = 1 + √2 ≈ 2.414) is the mathematical foundation of SilverVPN, used for timing, padding, and load balancing.",
            "help": "I can help with: connecting to servers, privacy settings, troubleshooting, and explaining silver ratio concepts. What would you like to know?",
        }

    async def generate(
        self,
        messages: List[Dict[str, Any]],
        config: AssistantConfig,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate mock response."""
        return self.generate_sync(messages, config, tools)

    def generate_sync(
        self,
        messages: List[Dict[str, Any]],
        config: AssistantConfig,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate mock response."""
        # Get last user message
        last_user_msg = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                last_user_msg = msg.get("content", "").lower()
                break

        # Match response based on keywords
        response_text = self._responses["default"]
        for keyword, response in self._responses.items():
            if keyword in last_user_msg:
                response_text = response
                break

        return {
            "message": {
                "role": "assistant",
                "content": response_text,
            },
            "eval_count": len(response_text) // 4,
            "eval_duration": 100_000_000,  # 100ms in nanoseconds
        }

    def set_response(self, keyword: str, response: str) -> None:
        """Set a custom response for a keyword."""
        self._responses[keyword] = response


class ChatEngine:
    """
    Main chat engine.

    Orchestrates conversations, knowledge, context, and tool execution.
    """

    def __init__(
        self,
        config: Optional[AssistantConfig] = None,
        backend: Optional[LLMBackend] = None,
    ):
        """
        Initialize chat engine.

        Args:
            config: Assistant configuration
            backend: LLM backend to use
        """
        self.config = config or AssistantConfig()

        # Initialize backend
        if backend:
            self.backend = backend
        elif self.config.backend == "ollama":
            self.backend = OllamaBackend(self.config.api_base_url)
        else:
            self.backend = MockBackend()

        # Initialize components
        self.knowledge = KnowledgeBase()
        self.context_manager = ContextManager()
        self.window = SlidingWindowContext(max_tokens=4096)
        self.vpn_tools = VPNTools()
        self.tool_registry = self.vpn_tools.get_registry()

    def create_conversation(self, user_id: Optional[str] = None) -> Conversation:
        """Create a new conversation with system prompt."""
        conversation = self.context_manager.create_conversation(user_id)

        # Add system message
        system_prompt = self.config.get_system_prompt()
        system_message = Message.system(system_prompt)
        conversation.add_message(system_message)

        return conversation

    def chat(
        self,
        user_input: str,
        conversation_id: Optional[str] = None,
    ) -> AssistantResponse:
        """
        Process a user message and generate a response.

        Args:
            user_input: The user's message
            conversation_id: ID of existing conversation (creates new if None)

        Returns:
            AssistantResponse with the assistant's reply
        """
        start_time = time.time()

        # Get or create conversation
        if conversation_id:
            conversation = self.context_manager.get_conversation(conversation_id)
            if conversation is None:
                conversation = self.create_conversation()
        else:
            conversation = self.create_conversation()

        # Add user message
        user_message = Message.user(user_input)
        conversation.add_message(user_message)

        # Build context with knowledge
        messages = self._build_messages(conversation, user_input)

        # Get tool schemas if enabled
        tools = None
        if self.config.enable_tools:
            tools = self.tool_registry.get_all_schemas()

        # Generate response
        result = self.backend.generate_sync(messages, self.config, tools)

        # Parse response
        response_content = ""
        tool_calls = None

        if "error" in result:
            response_content = result.get("message", {}).get("content", "An error occurred.")
        else:
            message_data = result.get("message", {})
            response_content = message_data.get("content", "")

            # Handle tool calls
            if "tool_calls" in message_data:
                tool_calls = self._parse_tool_calls(message_data["tool_calls"])

        # Execute tool calls if any
        tool_results = None
        if tool_calls:
            tool_results = self._execute_tool_calls(tool_calls)

            # If we have tool results, we might want to generate a follow-up response
            if tool_results:
                # Add tool results context
                tool_context = self._format_tool_results(tool_results)
                response_content = f"{response_content}\n\n{tool_context}" if response_content else tool_context

        # Create assistant message
        assistant_message = Message.assistant(response_content, tool_calls)
        assistant_message.tool_results = tool_results
        assistant_message.tokens_used = result.get("eval_count", 0)
        conversation.add_message(assistant_message)

        # Calculate timing
        generation_time = (time.time() - start_time) * 1000

        return AssistantResponse(
            content=response_content,
            conversation_id=conversation.conversation_id,
            message_id=assistant_message.message_id,
            model_used=self.config.model_name,
            tokens_used=assistant_message.tokens_used,
            generation_time_ms=generation_time,
            tool_calls=tool_calls,
            tool_results=tool_results,
        )

    async def chat_async(
        self,
        user_input: str,
        conversation_id: Optional[str] = None,
    ) -> AssistantResponse:
        """Async version of chat."""
        start_time = time.time()

        # Get or create conversation
        if conversation_id:
            conversation = self.context_manager.get_conversation(conversation_id)
            if conversation is None:
                conversation = self.create_conversation()
        else:
            conversation = self.create_conversation()

        # Add user message
        user_message = Message.user(user_input)
        conversation.add_message(user_message)

        # Build context with knowledge
        messages = self._build_messages(conversation, user_input)

        # Get tool schemas if enabled
        tools = None
        if self.config.enable_tools:
            tools = self.tool_registry.get_all_schemas()

        # Generate response
        result = await self.backend.generate(messages, self.config, tools)

        # Parse response (same as sync)
        response_content = ""
        tool_calls = None

        if "error" in result:
            response_content = result.get("message", {}).get("content", "An error occurred.")
        else:
            message_data = result.get("message", {})
            response_content = message_data.get("content", "")

            if "tool_calls" in message_data:
                tool_calls = self._parse_tool_calls(message_data["tool_calls"])

        tool_results = None
        if tool_calls:
            tool_results = self._execute_tool_calls(tool_calls)
            if tool_results:
                tool_context = self._format_tool_results(tool_results)
                response_content = f"{response_content}\n\n{tool_context}" if response_content else tool_context

        assistant_message = Message.assistant(response_content, tool_calls)
        assistant_message.tool_results = tool_results
        assistant_message.tokens_used = result.get("eval_count", 0)
        conversation.add_message(assistant_message)

        generation_time = (time.time() - start_time) * 1000

        return AssistantResponse(
            content=response_content,
            conversation_id=conversation.conversation_id,
            message_id=assistant_message.message_id,
            model_used=self.config.model_name,
            tokens_used=assistant_message.tokens_used,
            generation_time_ms=generation_time,
            tool_calls=tool_calls,
            tool_results=tool_results,
        )

    def _build_messages(
        self,
        conversation: Conversation,
        current_query: str,
    ) -> List[Dict[str, Any]]:
        """Build messages list with context."""
        messages = []

        # Get conversation messages
        conv_messages = conversation.get_messages_for_context(self.config.max_context_messages)

        # Add knowledge context to system message if enabled
        if self.config.include_knowledge_base:
            knowledge_context = self.knowledge.get_context_for_query(current_query)

            if knowledge_context and conv_messages:
                # Find system message and append knowledge
                for i, msg in enumerate(conv_messages):
                    if msg.role == MessageRole.SYSTEM:
                        enhanced_content = f"{msg.content}\n\n{knowledge_context}"
                        conv_messages[i] = Message.system(enhanced_content)
                        break

        # Convert to API format
        for msg in conv_messages:
            messages.append(msg.to_dict())

        return messages

    def _parse_tool_calls(self, tool_calls_data: List[Dict[str, Any]]) -> List[ToolCall]:
        """Parse tool calls from LLM response."""
        tool_calls = []

        for tc in tool_calls_data:
            function_data = tc.get("function", tc)
            tool_calls.append(ToolCall(
                tool_id=tc.get("id", str(uuid.uuid4())),
                tool_name=function_data.get("name", ""),
                arguments=function_data.get("arguments", {}),
            ))

        return tool_calls

    def _execute_tool_calls(self, tool_calls: List[ToolCall]) -> List[ToolResult]:
        """Execute tool calls and return results."""
        results = []

        for tc in tool_calls:
            try:
                result = self.tool_registry.execute(tc.tool_name, **tc.arguments)
                results.append(ToolResult(
                    tool_id=tc.tool_id,
                    tool_name=tc.tool_name,
                    result=result,
                    success=True,
                ))
            except Exception as e:
                results.append(ToolResult(
                    tool_id=tc.tool_id,
                    tool_name=tc.tool_name,
                    result=None,
                    success=False,
                    error=str(e),
                ))

        return results

    def _format_tool_results(self, results: List[ToolResult]) -> str:
        """Format tool results for display."""
        parts = []

        for result in results:
            if result.success:
                if isinstance(result.result, dict):
                    # Format dict nicely
                    formatted = json.dumps(result.result, indent=2)
                    parts.append(f"**{result.tool_name}**:\n```json\n{formatted}\n```")
                else:
                    parts.append(f"**{result.tool_name}**: {result.result}")
            else:
                parts.append(f"**{result.tool_name}** failed: {result.error}")

        return "\n\n".join(parts)

    def get_conversation(self, conversation_id: str) -> Optional[Conversation]:
        """Get a conversation by ID."""
        return self.context_manager.get_conversation(conversation_id)

    def clear_conversation(self, conversation_id: str) -> bool:
        """Clear a conversation's history."""
        return self.context_manager.clear_conversation(conversation_id)

    def list_topics(self) -> List[str]:
        """List available knowledge topics."""
        return self.knowledge.list_topics()

    def list_tools(self) -> List[str]:
        """List available tools."""
        return self.tool_registry.list_tools()

    def execute_tool(self, tool_name: str, **kwargs) -> Any:
        """Execute a tool directly."""
        return self.tool_registry.execute(tool_name, **kwargs)
