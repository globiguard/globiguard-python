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
