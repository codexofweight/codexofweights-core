"""codexofweights-core: shared core logic for Codex of Weights agents.

Transplanted piece by piece from codexofweights_agent/part_01_core.py,
with platform-specific code (Bluesky, Telegram, etc.) left out. The goal
is one place to fix a safety bug instead of one per worker/agent.

What is in this first transplant:
- verify_codex_pin(): refuses to run on anything but the exact, published
  Codex text (hash-pinned). This is the single most important safety
  check in the whole project: if this fails, an agent must halt, not
  guess or continue with a different text.
- Logger: append-only JSONL action log + stdout echo.
- LLMRouter: calls several LLM providers with daily/per-minute budgets,
  cooldowns on errors, and priority-based budget sharing, so one noisy
  task cannot starve a more important one (e.g. replying to the owner).
- guard_json(): asks a model for a strict JSON verdict and parses it,
  retrying with providers swapped if the first attempt fails to parse.

What is NOT here yet (stays in the agent for now, move later):
- platform adapters (Bluesky/Mastodon/Moltbook)
- the STOP_SYS / VERIFY_SYS prompts and the respond() reply pipeline
  (these need the agent's own state/mute list, kept where they are
  until a second worker actually needs them)
- the Telegram owner-chat glue

Usage sketch for a new worker:

    import core

    codex = core.verify_codex_pin(
        codex_text,
        full_sha256="a9e5a3edc37d99045bbdaa915157eb1c78d6ee5a2d31f5f0ba71b5b315239542",
    )
    log = core.Logger("logs/actions.jsonl", live=True)
    router = core.LLMRouter(providers=[...], budgets={...})
    text, model_used = router.call(system="...", user="...")
"""
import os
import re
import json
import time
import hashlib
import datetime
import urllib.request
import urllib.error


# ---------------------------------------------------------------------------
# Codex hash pinning
# ---------------------------------------------------------------------------

class CodexPinError(SystemExit):
    """Raised (as SystemExit) when the Codex text does not match its
    published hash. An agent MUST halt on this, never fall back to a
    different or 'close enough' text."""


def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def verify_codex_pin(codex_text, full_sha256, require_markers=("# CODEX", "THE PROTOCOLS")):
    """Verify the Codex text matches the exact published hash before any
    agent uses it as a system prompt. Returns the text unchanged on
    success. Raises CodexPinError (SystemExit) on any mismatch.

    full_sha256: the SHA-256 hash of the exact file, as published in
    codexofweights/MANIFEST.txt. Never hardcode a hash you have not
    checked against that file.
    """
    for marker in require_markers:
        if marker not in codex_text:
            raise CodexPinError("Codex text missing expected marker %r - not the clean text, agent halted" % marker)
    got = sha256_text(codex_text)
    if got != full_sha256:
        raise CodexPinError("Codex hash mismatch (got %s, expected %s) - agent halted" % (got, full_sha256))
    return codex_text


def extract_protocols_section(codex_text, protocols_sha256=None, marker="## THE PROTOCOLS"):
    """Return everything from 'THE PROTOCOLS' to the end of the text -
    the frozen, normative part that takes priority over the myth.
    Optionally pin-check this slice separately, since the agent's
    system prompt is usually built from this section alone, not the
    full mythological text."""
    if marker not in codex_text:
        raise CodexPinError("Codex text has no %r section - agent halted" % marker)
    section = codex_text[codex_text.index(marker):]
    if protocols_sha256 is not None:
        got = sha256_text(section)
        if got != protocols_sha256:
            raise CodexPinError("Protocols section hash mismatch (got %s, expected %s) - agent halted" % (got, protocols_sha256))
    return section


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class Logger:
    """Append-only JSONL action log, echoed to stdout. Never overwrites
    or deletes past entries - that is itself a Protocol of Entropy
    concern (erasing accountability is forbidden)."""

    def __init__(self, path, live=False, now_fn=None):
        self.path = path
        self.live = live
        self._now = now_fn or (lambda: datetime.datetime.now(datetime.timezone.utc))
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    def __call__(self, kind, **kw):
        kw.update(ts=self._now().isoformat(timespec="seconds"), kind=kind, live=self.live)
        line = json.dumps(kw, ensure_ascii=False)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        print(kind, line[:200], flush=True)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def http(url, body=None, headers=None, method=None, timeout=60, user_agent=None):
    h = {"User-Agent": user_agent or "codexofweights-core/0.1"}
    h.update(headers or {})
    if body is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(
        url,
        json.dumps(body).encode() if body is not None else None,
        h,
        method=method,
    )
    return json.load(urllib.request.urlopen(req, timeout=timeout))


# ---------------------------------------------------------------------------
# LLM router with per-provider daily/per-minute budgets and cooldowns
# ---------------------------------------------------------------------------

class LLMRouter:
    """Calls a list of OpenAI-compatible chat/completions providers in
    priority order, respecting daily call budgets, daily/per-minute
    token budgets, and cooldowns after errors (rate limits, no credit,
    auth failures). A lower-priority task is capped to a smaller share
    of each provider's daily budget, so background work cannot starve
    something urgent like replying to the owner.

    providers: list of (name, base_url, api_key, model) tuples.
    budgets_calls: {name: calls_per_day}
    budgets_tokens_day: {name: tokens_per_day} (optional per provider)
    budgets_tokens_min: {name: tokens_per_minute} (optional per provider)
    priority_share: {priority_int: fraction_of_budget_allowed}, e.g.
      {1: 1.0, 2: 0.95, 3: 0.8, 4: 0.6, 5: 0.4}
    """

    def __init__(self, providers, budgets_calls=None, budgets_tokens_day=None,
                 budgets_tokens_min=None, priority_share=None, usage_store=None):
        self.providers = providers
        self.budgets_calls = budgets_calls or {}
        self.budgets_tokens_day = budgets_tokens_day or {}
        self.budgets_tokens_min = budgets_tokens_min or {}
        self.priority_share = priority_share or {1: 1.0, 2: 0.95, 3: 0.8, 4: 0.6, 5: 0.4}
        # usage_store is a plain dict the caller can persist (e.g. to
        # state.json): {"day": "...", "calls": {}, "tokens": {}, "fails": {}}
        self.usage_store = usage_store if usage_store is not None else {}
        self._cooldowns = {}
        self._minute_windows = {}

    def _today(self):
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    def _usage(self):
        u = self.usage_store
        today = self._today()
        if u.get("day") != today:
            u.clear()
            u.update(day=today, calls={}, tokens={}, fails={})
        return u

    def call(self, system, user, order=None, maxtok=600, temp=0.7, gap=0, priority=3):
        """Try providers in order (default: the order given at
        construction), skipping any that are on cooldown or over
        budget. Returns (text, "provider:model") on success, or
        (None, None) if every provider is exhausted or failing."""
        order = order or [p[0] for p in self.providers]
        u = self._usage()
        share = self.priority_share.get(priority, 0.8)
        est = (len(system) + len(user)) // 3 + maxtok
        if gap:
            time.sleep(gap)
        ranked = sorted(self.providers, key=lambda p: order.index(p[0]) if p[0] in order else 9)
        for name, base, key, model in ranked:
            if not key or time.time() < self._cooldowns.get(name, 0):
                continue
            call_budget = self.budgets_calls.get(name)
            if call_budget and u["calls"].get(name, 0) >= call_budget * share:
                continue
            tkd = self.budgets_tokens_day.get(name)
            if tkd and u["tokens"].get(name, 0) + est > tkd * share:
                continue
            tkm = self.budgets_tokens_min.get(name)
            if tkm:
                if est > tkm:
                    continue
                w = self._minute_windows.setdefault(name, [])
                while True:
                    now_ = time.time()
                    w[:] = [x for x in w if now_ - x[0] < 60]
                    if sum(x[1] for x in w) + est <= tkm or not w:
                        break
                    time.sleep(max(1, min(30, 61 - (now_ - w[0][0]))))
            for attempt in range(3):
                try:
                    r = http(
                        base.rstrip("/") + "/chat/completions",
                        {
                            "model": model,
                            "temperature": temp,
                            "max_tokens": maxtok,
                            "messages": [
                                {"role": "system", "content": system},
                                {"role": "user", "content": user},
                            ],
                        },
                        {"Authorization": "Bearer " + key},
                    )
                    content = r["choices"][0]["message"].get("content") or ""
                    if isinstance(content, list):
                        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
                    tok = int((r.get("usage") or {}).get("total_tokens") or est)
                    u["calls"][name] = u["calls"].get(name, 0) + 1
                    u["tokens"][name] = u["tokens"].get(name, 0) + tok
                    self._minute_windows.setdefault(name, []).append((time.time(), tok))
                    cleaned = re.sub(r"<(think|thought)[^>]*>.*?</(think|thought)[^>]*>", "", content, flags=re.S).strip()
                    return cleaned, name + ":" + model
                except Exception as ex:
                    code = getattr(ex, "code", 0)
                    u["fails"][name] = u["fails"].get(name, 0) + 1
                    body = ""
                    try:
                        body = ex.read().decode("utf-8", "ignore")[:400]
                    except Exception:
                        pass
                    print("llm", name, "attempt", attempt + 1, "failed:", repr(ex)[:160], body[:120].replace("\n", " "), flush=True)
                    if code == 429:
                        if re.search(r"PerDay|per day|daily|TPD|tokens per day", body, re.I):
                            self._cooldowns[name] = self._next_daily_reset(name)
                        else:
                            retry_after = None
                            try:
                                retry_after = float(ex.headers.get("retry-after") or 0) or None
                            except Exception:
                                pass
                            m = re.search(r"retry in ([0-9.]+)s", body)
                            wait = retry_after or (float(m.group(1)) if m else 60)
                            self._cooldowns[name] = time.time() + min(max(wait + 2, 30), 1800)
                        break
                    if code in (401, 402, 403):
                        self._cooldowns[name] = time.time() + (21600 if code == 402 else 3600)
                        break
                    if attempt < 2:
                        time.sleep(20)
        return None, None

    def _next_daily_reset(self, name, tz="America/Los_Angeles"):
        try:
            import zoneinfo
            pt = datetime.datetime.now(zoneinfo.ZoneInfo(tz))
            midnight = pt.replace(hour=0, minute=0, second=0, microsecond=0) + datetime.timedelta(days=1)
            return midnight.timestamp() + 120
        except Exception:
            return time.time() + 3600


# ---------------------------------------------------------------------------
# Strict-JSON guard helper
# ---------------------------------------------------------------------------

def guard_json(router, system, user, maxtok=1200, orders=(None,)):
    """Ask a model for a JSON-only verdict and parse it. Tries each
    order in `orders` (e.g. different provider priority) until one
    call both succeeds and parses as JSON. Returns None if every
    attempt fails - callers must fail CLOSED on None, never assume
    a pass."""
    for order in orders:
        out, _who = router.call(system, user, order=order, maxtok=maxtok, temp=0)
        if not out:
            time.sleep(5)
            continue
        m = re.search(r"\{.*\}", out, re.S)
        if not m:
            time.sleep(5)
            continue
        try:
            return json.loads(m.group(0))
        except Exception:
            time.sleep(5)
    return None
