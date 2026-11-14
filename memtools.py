"""codexofweights-core: generic building blocks for GitHub-backed memory.

Transplanted (the reusable half) from
codexofweights_agent/part_02_memory.py. The agent-specific part of
that file - which facts go where in ONE agent's private repo, the
link-graph over ITS own people/topics, mem_context()/learn() tuned to
its own state - stays in the agent, because it is tightly coupled to
one MEM_REPO layout and one agent's globals. What is generic and
reusable by any future worker that needs its own small persisted
memory is just: read/write a text file in a private GitHub repo via
the Contents API (with the required read-before-write SHA), and
compare pieces of text by meaning or by keyword.

Usage sketch:

    store = GitHubFileStore(repo="owner/private-memory-repo", token=os.environ["MEM_TOKEN"])
    notes = store.get("people/alice.md") or ""
    store.put("people/alice.md", notes + "\\n- met at conference")

    v1 = embed(router, "likes long walks")
    v2 = embed(router, "enjoys hiking")
    cosine(v1, v2)  # similarity, 0..1 roughly
"""
import base64
import json
import math
import re
import urllib.request
import urllib.error


class GitHubFileStore:
    """Minimal read/write access to text files in one GitHub repo via
    the Contents API. The GitHub Contents API requires the file's
    current `sha` on every update (optimistic locking) - this class
    always re-fetches it immediately before writing, so two workers
    writing the same file close together fail loudly (409) instead of
    silently clobbering each other."""

    def __init__(self, repo, token, branch="main", user_agent="codexofweights-core/0.1"):
        self.repo = repo  # "owner/name"
        self.token = token
        self.branch = branch
        self.user_agent = user_agent

    def _req(self, path, method="GET", body=None):
        url = "https://api.github.com/repos/%s/contents/%s" % (self.repo, path.lstrip("/"))
        headers = {
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "User-Agent": self.user_agent,
        }
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        return json.load(urllib.request.urlopen(req, timeout=30))

    def get(self, path, default=None):
        """Return the file's text content, or `default` if it does not
        exist (any other HTTP error is raised, not swallowed)."""
        try:
            r = self._req(path + "?ref=" + self.branch)
        except urllib.error.HTTPError as ex:
            if ex.code == 404:
                return default
            raise
        return base64.b64decode(r["content"]).decode("utf-8", "replace")

    def put(self, path, text, message=None):
        """Create or update a file with the given text content.
        Always re-reads the current sha first, so this is safe to call
        even if another process may have changed the file since the
        caller last read it (the caller still loses that race, but
        loudly, via a GitHub 409, rather than silently)."""
        sha = None
        try:
            sha = self._req(path + "?ref=" + self.branch).get("sha")
        except urllib.error.HTTPError as ex:
            if ex.code != 404:
                raise
        body = {
            "message": message or ("update " + path),
            "content": base64.b64encode(text.encode("utf-8")).decode(),
            "branch": self.branch,
        }
        if sha:
            body["sha"] = sha
        return self._req(path, method="PUT", body=body)


# ---------------------------------------------------------------------------
# Similarity helpers
# ---------------------------------------------------------------------------

def embed(router, text, model="models/text-embedding-004", dim=128):
    """Get a fixed-size embedding vector for `text` via an
    OpenAI-compatible /embeddings endpoint reached through the same
    kind of (name, base_url, api_key, model) provider tuple core.LLMRouter
    uses. Returns None on failure - callers should fall back to `kws()`
    below, not treat None as a zero vector."""
    for name, base, key, mdl in router.providers:
        if not key:
            continue
        try:
            import core
            r = core.http(
                base.rstrip("/") + "/embeddings",
                {"model": model or mdl, "input": text[:8000]},
                {"Authorization": "Bearer " + key},
            )
            vec = r["data"][0]["embedding"]
            return vec[:dim]
        except Exception:
            continue
    return None


def cosine(v1, v2):
    """Cosine similarity of two equal-length vectors, 0 if either is
    missing/zero-length."""
    if not v1 or not v2:
        return 0.0
    n = min(len(v1), len(v2))
    v1, v2 = v1[:n], v2[:n]
    dot = sum(a * b for a, b in zip(v1, v2))
    m1 = math.sqrt(sum(a * a for a in v1))
    m2 = math.sqrt(sum(b * b for b in v2))
    if not m1 or not m2:
        return 0.0
    return dot / (m1 * m2)


_STOP = set(
    "a an the and or but of to in on for with is are was were be been being "
    "this that it its as at by from into over under not no so if then than".split()
)


def kws(text):
    """Keyword set for a piece of text (lowercased word tokens, stop
    words removed) - the fallback similarity measure when no embedding
    provider is reachable."""
    return {w for w in re.findall(r"[a-zA-Z']+", (text or "").lower()) if len(w) > 2 and w not in _STOP}


def jaccard(a, b):
    """Jaccard similarity between two keyword sets from `kws()`."""
    a, b = set(a), set(b)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)
