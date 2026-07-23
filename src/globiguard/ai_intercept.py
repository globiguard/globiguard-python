"""Generic AI provider intercept for governed calls."""
from __future__ import annotations
import functools
from typing import TYPE_CHECKING, Any, Callable
from .governed_actions import GovernedActionsClient
from .errors import GlobiguardAuthorityError

if TYPE_CHECKING:
    from .brain import BrainClient


class AiIntercept:
    def __init__(
        self,
        governed_actions: GovernedActionsClient,
        *,
        brain: BrainClient | None = None,
        action_type: str = "ai.request",
        destination: str = "ai_model",
        mode: str = "scan_both",  # scan_input | scan_output | scan_both
        on_block: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._governed = governed_actions
        self._brain = brain
        self._action_type = action_type
        self._destination = destination
        self._mode = mode
        self._on_block = on_block

    def wrap(self, input_text: str, call_fn: Callable[..., Any], **call_kwargs: Any) -> dict[str, Any]:
        input_decision = None
        output_decision = None

        if self._mode in ("scan_input", "scan_both"):
            input_decision = self._governed.detect_and_authorize({
                "text": input_text,
                "action_type": self._action_type,
                "destination": {"type": "ai_model", "name": self._destination},
            })
            if isinstance(input_decision, dict) and input_decision.get("decision") == "BLOCK":
                if self._on_block:
                    self._on_block(input_decision)
                raise GlobiguardAuthorityError(
                    kind="POLICY_BLOCKED",
                    message="GlobiGuard blocked the AI input.",
                    authorization_id=input_decision.get("authorizationId"),
                )

        response = call_fn(**call_kwargs)

        if self._mode in ("scan_output", "scan_both") and self._brain is not None:
            output_text = _extract_text(response)
            if output_text:
                classification = self._brain.classify({"text": output_text})
                data_class = classification.get("dataClass") or classification.get("data_class") or "PUBLIC"
                if data_class in ("RESTRICTED", "SECRET", "PII", "PHI", "PCI"):
                    output_decision = self._governed.authorize_action({
                        "context": {
                            "actionType": "ai.response",
                            "destination": {"type": "ai_model", "name": self._destination},
                            "dataClasses": [data_class],
                        }
                    })

        return {
            "response": response,
            "input_decision": input_decision,
            "output_decision": output_decision,
        }

    def openai(self, client: Any) -> Any:
        return _OpenAIClientProxy(client, self)

    def anthropic(self, client: Any) -> Any:
        return _AnthropicClientProxy(client, self)

    def google(self, model: Any) -> Any:
        """Wrap a google.generativeai GenerativeModel's generate_content."""
        return _GoogleModelProxy(model, self)

    def bedrock(self, client: Any) -> Any:
        """Wrap an AWS Bedrock runtime client's converse method."""
        return _BedrockClientProxy(client, self)

    def cohere(self, client: Any) -> Any:
        """Wrap a Cohere client's chat method."""
        return _CohereClientProxy(client, self)

    def mistral(self, client: Any) -> Any:
        """Wrap a Mistral client's chat.complete method."""
        return _MistralClientProxy(client, self)

    def ollama(self, client: Any) -> Any:
        """Wrap an Ollama client's chat method."""
        return _OllamaClientProxy(client, self)

    def langchain_callback(self) -> Any:
        """Return a LangChain BaseCallbackHandler that governs LLM calls.

        Usage:
            handler = intercept.langchain_callback()
            llm.invoke("...", config={"callbacks": [handler]})
        """
        try:
            from langchain_core.callbacks import BaseCallbackHandler
        except ImportError:
            from langchain.callbacks.base import BaseCallbackHandler  # type: ignore[no-redef]

        intercept = self

        class GlobiguardLangChainCallback(BaseCallbackHandler):
            def __init__(self) -> None:
                super().__init__()
                self._intercept = intercept

            def on_chat_model_start(self, serialized: Any, messages: Any, **kwargs: Any) -> None:
                if self._intercept._mode not in ("scan_input", "scan_both"):
                    return
                flat = " ".join(
                    getattr(m, "content", "")
                    for batch in messages
                    for m in batch
                    if isinstance(getattr(m, "content", None), str)
                )
                decision = self._intercept._governed.detect_and_authorize({
                    "text": flat,
                    "action_type": self._intercept._action_type,
                    "destination": {"type": "ai_model", "name": self._intercept._destination},
                })
                if isinstance(decision, dict) and decision.get("decision") == "BLOCK":
                    if self._intercept._on_block:
                        self._intercept._on_block(decision)
                    raise GlobiguardAuthorityError(
                        kind="POLICY_BLOCKED",
                        message="GlobiGuard blocked the AI input.",
                        authorization_id=decision.get("authorizationId"),
                    )

            def on_llm_end(self, response: Any, **kwargs: Any) -> None:
                if self._intercept._mode not in ("scan_output", "scan_both"):
                    return
                if self._intercept._brain is None:
                    return
                try:
                    output_text = response.generations[0][0].text
                except (IndexError, AttributeError):
                    return
                if not output_text:
                    return
                classification = self._intercept._brain.classify({"text": output_text})
                data_class = classification.get("dataClass") or classification.get("data_class") or "PUBLIC"
                if data_class in ("RESTRICTED", "SECRET", "PII", "PHI", "PCI"):
                    decision = self._intercept._governed.authorize_action({
                        "context": {
                            "actionType": "ai.response",
                            "destination": {"type": "ai_model", "name": self._intercept._destination},
                            "dataClasses": [data_class],
                        }
                    })
                    if isinstance(decision, dict) and decision.get("decision") == "BLOCK":
                        if self._intercept._on_block:
                            self._intercept._on_block(decision)
                        raise GlobiguardAuthorityError(
                            kind="POLICY_BLOCKED",
                            message="GlobiGuard blocked the AI output.",
                            authorization_id=decision.get("authorizationId"),
                        )

            def on_llm_error(self, error: Any, **kwargs: Any) -> None:
                pass

        return GlobiguardLangChainCallback()

    def llamaindex_callback(self) -> Any:
        """Return a LlamaIndex BaseCallbackHandler that governs LLM calls.

        Usage:
            from llama_index.core import Settings
            from llama_index.core.callbacks import CallbackManager
            Settings.callback_manager = CallbackManager([intercept.llamaindex_callback()])
        """
        from llama_index.core.callbacks import BaseCallbackHandler, CBEventType

        intercept = self

        class GlobiguardLlamaIndexCallback(BaseCallbackHandler):
            def __init__(self) -> None:
                super().__init__(event_starts_to_ignore=[], event_ends_to_ignore=[])
                self._intercept = intercept

            def on_event_start(
                self,
                event_type: Any,
                payload: Any = None,
                event_id: str = "",
                parent_id: str = "",
                **kwargs: Any,
            ) -> str:
                if event_type != CBEventType.LLM:
                    return event_id
                if payload is None or self._intercept._mode not in ("scan_input", "scan_both"):
                    return event_id
                try:
                    from llama_index.core.callbacks import EventPayload
                    messages = payload.get(EventPayload.MESSAGES)
                    if messages:
                        input_text = " ".join(
                            getattr(m, "content", str(m))
                            for m in messages
                            if isinstance(getattr(m, "content", None), str)
                        )
                    else:
                        prompt = payload.get(EventPayload.PROMPT, "")
                        input_text = str(prompt) if prompt else ""
                except Exception:
                    return event_id
                if not input_text:
                    return event_id
                decision = self._intercept._governed.detect_and_authorize({
                    "text": input_text,
                    "action_type": self._intercept._action_type,
                    "destination": {"type": "ai_model", "name": self._intercept._destination},
                })
                if isinstance(decision, dict) and decision.get("decision") == "BLOCK":
                    if self._intercept._on_block:
                        self._intercept._on_block(decision)
                    raise GlobiguardAuthorityError(
                        kind="POLICY_BLOCKED",
                        message="GlobiGuard blocked the AI input.",
                        authorization_id=decision.get("authorizationId"),
                    )
                return event_id

            def on_event_end(
                self,
                event_type: Any,
                payload: Any = None,
                event_id: str = "",
                **kwargs: Any,
            ) -> None:
                if event_type != CBEventType.LLM:
                    return
                if payload is None or self._intercept._brain is None:
                    return
                if self._intercept._mode not in ("scan_output", "scan_both"):
                    return
                try:
                    from llama_index.core.callbacks import EventPayload
                    response = payload.get(EventPayload.RESPONSE) or payload.get(EventPayload.COMPLETION)
                    output_text = getattr(response, "text", None) if response is not None else None
                    if not isinstance(output_text, str):
                        output_text = str(response) if response is not None else ""
                except Exception:
                    return
                if not output_text:
                    return
                classification = self._intercept._brain.classify({"text": output_text})
                data_class = classification.get("dataClass") or classification.get("data_class") or "PUBLIC"
                if data_class in ("RESTRICTED", "SECRET", "PII", "PHI", "PCI"):
                    decision = self._intercept._governed.authorize_action({
                        "context": {
                            "actionType": "ai.response",
                            "destination": {"type": "ai_model", "name": self._intercept._destination},
                            "dataClasses": [data_class],
                        }
                    })
                    if isinstance(decision, dict) and decision.get("decision") == "BLOCK":
                        if self._intercept._on_block:
                            self._intercept._on_block(decision)
                        raise GlobiguardAuthorityError(
                            kind="POLICY_BLOCKED",
                            message="GlobiGuard blocked the AI output.",
                            authorization_id=decision.get("authorizationId"),
                        )

        return GlobiguardLlamaIndexCallback()

    def generic(self, call_fn: Callable[..., Any], *, extract_input: Callable[..., str] | None = None) -> Callable[..., Any]:
        """Return a governed wrapper around any callable AI provider.

        extract_input: called with the same kwargs as call_fn to produce the text
        that Brain scans. If omitted, no input scan is performed.
        """
        intercept = self

        @functools.wraps(call_fn)
        def governed(**kwargs: Any) -> Any:
            input_text = extract_input(**kwargs) if extract_input is not None else ""
            return intercept.wrap(input_text, call_fn, **kwargs)["response"]

        return governed


class _OpenAICompletionsProxy:
    def __init__(self, completions: Any, intercept: AiIntercept) -> None:
        self._completions = completions
        self._intercept = intercept
        self.create = self._governed_create

    def _governed_create(self, **params: Any) -> Any:
        original_create = self._completions.create
        messages = params.get("messages", [])
        input_text = "\n".join(
            m.get("content", "") for m in messages if isinstance(m.get("content"), str)
        )
        return self._intercept.wrap(input_text, original_create, **params)["response"]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


class _OpenAIChatProxy:
    def __init__(self, chat: Any, intercept: AiIntercept) -> None:
        self._chat = chat
        self.completions = _OpenAICompletionsProxy(chat.completions, intercept)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


class _OpenAIClientProxy:
    def __init__(self, client: Any, intercept: AiIntercept) -> None:
        self._client = client
        self.chat = _OpenAIChatProxy(client.chat, intercept)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _AnthropicMessagesProxy:
    def __init__(self, messages: Any, intercept: AiIntercept) -> None:
        self._messages = messages
        self._intercept = intercept
        self.create = self._governed_create

    def _governed_create(self, **params: Any) -> Any:
        original_create = self._messages.create
        messages = params.get("messages", [])
        input_text = "\n".join(
            m.get("content", "") for m in messages if isinstance(m.get("content"), str)
        )
        return self._intercept.wrap(input_text, original_create, **params)["response"]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._messages, name)


class _AnthropicClientProxy:
    def __init__(self, client: Any, intercept: AiIntercept) -> None:
        self._client = client
        self.messages = _AnthropicMessagesProxy(client.messages, intercept)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _GoogleModelProxy:
    def __init__(self, model: Any, intercept: AiIntercept) -> None:
        self._model = model
        self._intercept = intercept

    def generate_content(self, contents: Any, **kwargs: Any) -> Any:
        if isinstance(contents, str):
            input_text = contents
        elif isinstance(contents, list):
            input_text = " ".join(p for p in contents if isinstance(p, str))
        else:
            input_text = str(contents)
        original = self._model.generate_content
        result = self._intercept.wrap(input_text, original, contents=contents, **kwargs)
        return result["response"]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._model, name)


class _BedrockClientProxy:
    def __init__(self, client: Any, intercept: AiIntercept) -> None:
        self._client = client
        self._intercept = intercept

    def converse(self, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        try:
            input_text = messages[-1]["content"][0]["text"]
        except (IndexError, KeyError, TypeError):
            input_text = ""
        original = self._client.converse
        result = self._intercept.wrap(input_text, original, **kwargs)
        return result["response"]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _CohereClientProxy:
    def __init__(self, client: Any, intercept: AiIntercept) -> None:
        self._client = client
        self._intercept = intercept

    def chat(self, **kwargs: Any) -> Any:
        if "message" in kwargs:
            input_text = kwargs["message"]
        else:
            messages = kwargs.get("messages", [])
            try:
                input_text = messages[-1].get("text", "") if messages else ""
            except (AttributeError, IndexError):
                input_text = ""
        original = self._client.chat
        result = self._intercept.wrap(input_text, original, **kwargs)
        return result["response"]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _MistralChatProxy:
    def __init__(self, chat: Any, intercept: AiIntercept) -> None:
        self._chat = chat
        self._intercept = intercept

    def complete(self, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        try:
            last = messages[-1]
            input_text = last.get("content", "") if isinstance(last, dict) else getattr(last, "content", "")
        except (IndexError, AttributeError):
            input_text = ""
        original = self._chat.complete
        result = self._intercept.wrap(input_text, original, **kwargs)
        return result["response"]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


class _MistralClientProxy:
    def __init__(self, client: Any, intercept: AiIntercept) -> None:
        self._client = client
        self.chat = _MistralChatProxy(client.chat, intercept)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _OllamaClientProxy:
    def __init__(self, client: Any, intercept: AiIntercept) -> None:
        self._client = client
        self._intercept = intercept

    def chat(self, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        try:
            last = messages[-1]
            input_text = last.get("content", "") if isinstance(last, dict) else getattr(last, "content", "")
        except (IndexError, AttributeError):
            input_text = ""
        original = self._client.chat
        result = self._intercept.wrap(input_text, original, **kwargs)
        return result["response"]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def _extract_text(response: Any) -> str | None:
    """Best-effort text extraction from common AI response shapes."""
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        choices = response.get("choices")
        if choices and isinstance(choices, list):
            msg = choices[0].get("message", {})
            return msg.get("content")
        content = response.get("content")
        if isinstance(content, list) and content:
            return content[0].get("text")
        if isinstance(content, str):
            return content
    try:
        choices = getattr(response, "choices", None)
        if choices:
            return getattr(getattr(choices[0], "message", None), "content", None)
        content = getattr(response, "content", None)
        if isinstance(content, list) and content:
            return getattr(content[0], "text", None)
        if isinstance(content, str):
            return content
    except Exception:
        pass
    return None
