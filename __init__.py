"""CRE-AgentProtect , Microsoft AGT adapter for HookBus.

Subscribes to HookBus PreToolUse / PostToolUse events. Translates them
into AGT SemanticPolicyEngine input format, runs the engine, returns
the verdict back to HookBus in the standard envelope.

Free, MIT. Adapter only , Microsoft maintains the engine.

For the enterprise tier, see agenticthinking.uk.
"""

from __future__ import annotations

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional

__version__ = "0.1.0"
logger = logging.getLogger(__name__)

# AGT , required dependency. Fail loud if missing so users install it.
try:
    from agent_os import SemanticPolicyEngine, IntentCategory
except ImportError as exc:
    raise ImportError(
        "CRE-AgentProtect requires Microsoft AGT (`pip install agent-os-kernel`). "
        "Install upstream Microsoft AGT before running CRE-AgentProtect."
    ) from exc

# Categories CRE-AgentProtect treats as deny-by-default. Match CRE Full L1 defaults.
_DENY_CATEGORIES = [
    IntentCategory.DESTRUCTIVE_DATA,
    IntentCategory.DATA_EXFILTRATION,
    IntentCategory.PRIVILEGE_ESCALATION,
    IntentCategory.SYSTEM_MODIFICATION,
]
_DEFAULT_CONFIDENCE = float(os.environ.get("CRE_AGENTPROTECT_CONFIDENCE_THRESHOLD", "0.5"))

_engine: Optional[SemanticPolicyEngine] = None


import secrets as _secrets
from pathlib import Path as _Path
import time as _time


def _load_token() -> str:
    """Load auth token. HOOKBUS_TOKEN env var takes priority, falls back to shared
    /root/.hookbus/.token file (written by the bus on first boot).

    On cold start, the bus may not have written the token file yet. Wait up to
    CRE_AGENTPROTECT_TOKEN_WAIT seconds (default 30) for it to appear before
    giving up."""
    env = os.environ.get("HOOKBUS_TOKEN", "").strip()
    if env:
        return env
    shared = _Path(os.environ.get("HOOKBUS_TOKEN_PATH", "/root/.hookbus/.token"))
    wait_s = int(os.environ.get("CRE_AGENTPROTECT_TOKEN_WAIT", "30"))
    deadline = _time.time() + wait_s
    logged = False
    while _time.time() < deadline:
        try:
            if shared.exists():
                content = shared.read_text().strip()
                if content:
                    return content
        except Exception:
            pass
        if not logged:
            print(f"[cre-agentprotect] waiting up to {wait_s}s for token file at {shared}...", flush=True)
            logged = True
        _time.sleep(1)
    return ""


_AUTH_TOKEN = _load_token()
if not _AUTH_TOKEN:
    import sys as _sys
    _sys.stderr.write(
        "FATAL: cre-agentprotect could not find an auth token. "
        "Set HOOKBUS_TOKEN env or mount /root/.hookbus shared with the bus.\n"
    )
    raise SystemExit(1)


def _get_engine() -> SemanticPolicyEngine:
    global _engine
    if _engine is None:
        _engine = SemanticPolicyEngine(
            deny=_DENY_CATEGORIES,
            confidence_threshold=_DEFAULT_CONFIDENCE,
        )
    return _engine


# Map common HookBus tool names → AGT tool types
_TOOL_TYPE_MAP = {
    "terminal_tool": "run_command",
    "bash":          "run_command",
    "shell":         "run_command",
    "execute_command": "run_command",
    "write_to_file": "write_file",
    "apply_diff":    "write_file",
    "insert_content": "write_file",
    "search_and_replace": "write_file",
    "edit":          "write_file",
}


def _to_agt_args(tool_name: str, tool_input: Dict[str, Any]):
    """Translate a HookBus PreToolUse event into AGT.classify() args."""
    agt_type = _TOOL_TYPE_MAP.get(tool_name, tool_name)
    if agt_type == "run_command":
        cmd = tool_input.get("command") or tool_input.get("cmd") or ""
        return agt_type, {"command": str(cmd)}
    if agt_type == "write_file":
        path = tool_input.get("file_path") or tool_input.get("path") or ""
        content = tool_input.get("content") or tool_input.get("new_content") or ""
        return agt_type, {"path": str(path), "content": str(content)[:2000]}
    # Generic fallback , pass tool_input through
    return agt_type, {k: str(v)[:500] for k, v in (tool_input or {}).items()}


def evaluate(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a HookBus envelope through AGT. Returns HookBus verdict envelope.

    Gates pre-action events through AGT classification:
      * PreToolUse      -> classify(tool, tool_input)
      * UserPromptSubmit -> classify("user_prompt", {"prompt": text})

    Observational events (PostToolUse, PostLLMCall, Stop) cannot be blocked
    post-hoc, so we record them as allow-with-context.
    """
    event_type = envelope.get("event_type", "")

    if event_type == "PreToolUse":
        tool_name = envelope.get("tool_name", "")
        tool_input = envelope.get("tool_input", {}) or {}
        agt_type, agt_params = _to_agt_args(tool_name, tool_input)
    elif event_type == "UserPromptSubmit":
        prompt_text = (
            envelope.get("prompt")
            or envelope.get("user_message")
            or envelope.get("tool_input", {}).get("prompt", "")
            or ""
        )
        agt_type = "user_prompt"
        agt_params = {"prompt": str(prompt_text)[:4000]}
    else:
        return {
            "decision": "allow",
            "reason": f"[cre-agentprotect] {event_type} observed (post-hoc)",
        }

    engine = _get_engine()
    try:
        result = engine.classify(agt_type, agt_params)
    except Exception as exc:
        logger.exception("AGT classify failed")
        return {"decision": "allow", "reason": "[cre-agentprotect] AGT classify error"}

    category = getattr(result, "category", None)
    confidence = float(getattr(result, "confidence", 0.0))
    explanation = getattr(result, "explanation", "")
    cat_name = getattr(category, "name", "NONE")

    if (category is not None
            and category != IntentCategory.BENIGN
            and category in _DENY_CATEGORIES
            and confidence >= _DEFAULT_CONFIDENCE):
        return {
            "decision": "deny",
            "reason": (
                f"[cre-agentprotect] AGT classified as {cat_name} "
                f"(confidence {confidence:.2f}): {explanation}".strip()
            ),
        }

    return {
        "decision": "allow",
        "reason": f"[cre-agentprotect] AGT clean ({cat_name} {confidence:.2f})",
    }


# ---------------------------------------------------------------------------
# HookBus subscriber HTTP server
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def _check_auth(self) -> bool:
        """Validate bearer token. Accepts Authorization header, ?token= query
        param, or hookbus_token cookie (same precedence as the bus)."""
        from urllib.parse import urlparse, parse_qs
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            candidate = h[7:].strip()
            if candidate and _secrets.compare_digest(candidate, _AUTH_TOKEN):
                return True
        q = parse_qs(urlparse(self.path).query)
        for v in q.get("token", []):
            if v and _secrets.compare_digest(v.strip(), _AUTH_TOKEN):
                return True
        cookie = self.headers.get("Cookie", "")
        for pair in cookie.split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                if k == "hookbus_token" and _secrets.compare_digest(v.strip(), _AUTH_TOKEN):
                    return True
        return False

    def _deny_401(self) -> None:
        body = json.dumps({
            "decision": "deny",
            "reason": "[cre-agentprotect] unauthorised",
        }).encode("utf-8")
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802 , http.server convention
        if not self._check_auth():
            return self._deny_401()
        event_id = ""
        try:
            length = int(self.headers.get("Content-Length", "0"))
            envelope = json.loads(self.rfile.read(length))
            event_id = envelope.get("event_id", "")
            verdict = evaluate(envelope)
        except Exception as exc:
            logger.exception("[cre-agentprotect] handler error")
            verdict = {"decision": "allow", "reason": "[cre-agentprotect] internal error"}
        # Echo event_id in response (HookBus correlates request/response by id)
        verdict["event_id"] = event_id
        verdict.setdefault("subscriber", "cre-agentprotect")
        body = json.dumps(verdict).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 , base class signature
        logger.info("%s - %s", self.address_string(), format % args)


def serve(host: str = "0.0.0.0", port: int = 8878) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [cre-agentprotect] %(message)s")
    logger.info(
        "CRE-AgentProtect v%s starting on %s:%s , AGT adapter (MIT).",
        __version__, host, port,
    )
    logger.info("For the enterprise tier: agenticthinking.uk")
    HTTPServer((host, port), _Handler).serve_forever()


if __name__ == "__main__":
    serve(
        host=os.environ.get("CRE_AGENTPROTECT_HOST", "0.0.0.0"),
        port=int(os.environ.get("CRE_AGENTPROTECT_PORT", "8878")),
    )
