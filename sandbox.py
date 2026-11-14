"""codexofweights-core: sandboxed execution of self-written tools.

Transplanted from codexofweights_agent/part_05_tools_sandbox.py. This is
the highest-risk piece of the whole project (it runs code an LLM wrote),
so it is also the piece most worth centralizing: one fix here reaches
every worker that uses it, instead of N copies drifting apart.

Isolation model (fail closed): a root-owned namespace cuts network,
processes and mounts; /home /root /tmp /var/tmp are replaced by empty
tmpfs (so the repository, state and every secret file are invisible to
the tool); the code runs as the unprivileged user 'nobody' with an
empty environment, no new privileges, and hard resource limits (CPU,
memory, open files, processes). The tool's code and payload travel
through stdin as JSON, so no file of the host process is ever exposed
to it. If any part of this cannot be verified (self-test fails, `sudo`/
`unshare` unavailable), tools do NOT run - there is no unisolated
fallback.

A static AST check runs BEFORE anything is executed: it rejects
disallowed imports, dangerous names (eval/exec/open/getattr/...),
underscore-attribute access, global/nonlocal, async defs, and requires
a single `run(payload)` entry point. The static check is a second
layer, not a replacement for the sandbox - both must hold.

Usage sketch:

    import sandbox

    box = sandbox.Sandbox()
    if not box.ready():
        # tools are disabled here; do not fall back to running code
        # outside the sandbox
        ...
    problems = sandbox.static_check(code)
    if problems:
        reject(problems)
    ok, result_or_error = box.run_code(code, payload, timeout=10)
"""
import ast
import json
import os
import shlex
import subprocess
import sys


DEFAULT_ALLOWED_IMPORTS = {
    "re", "json", "math", "statistics", "collections", "itertools",
    "functools", "datetime", "string", "textwrap", "difflib", "hashlib",
    "base64", "unicodedata", "heapq", "bisect", "random", "typing",
    "dataclasses", "decimal", "fractions", "html",
}

DEFAULT_BAD_NAMES = {
    "eval", "exec", "compile", "open", "__import__", "input", "globals",
    "locals", "vars", "getattr", "setattr", "delattr", "breakpoint",
    "exit", "quit", "memoryview", "type", "object", "super",
}


def static_check(code, allowed_imports=None, bad_names=None, max_len=12000):
    """Return a sorted list of problems found by static analysis (empty
    list = passed). Does not execute anything."""
    allowed_imports = allowed_imports if allowed_imports is not None else DEFAULT_ALLOWED_IMPORTS
    bad_names = bad_names if bad_names is not None else DEFAULT_BAD_NAMES
    bad = []
    try:
        tree = ast.parse(code)
    except SyntaxError as ex:
        return ["syntax error: %s" % ex]
    if len(code) > max_len:
        bad.append("too long")
    has_run = False
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            bad += ["import %s not allowed" % a.name for a in n.names if a.name.split(".")[0] not in allowed_imports]
        elif isinstance(n, ast.ImportFrom):
            if (n.module or "").split(".")[0] not in allowed_imports or n.level:
                bad.append("from %s import not allowed" % n.module)
        elif isinstance(n, ast.Name) and n.id in bad_names:
            bad.append("name %s not allowed" % n.id)
        elif isinstance(n, ast.Attribute) and n.attr.startswith("_"):
            bad.append("attribute %s not allowed" % n.attr)
        elif isinstance(n, (ast.Global, ast.Nonlocal, ast.AsyncFunctionDef, ast.Await)):
            bad.append("construct not allowed")
        elif isinstance(n, ast.FunctionDef) and n.name == "run":
            has_run = True
    if not has_run:
        bad.append("no run(payload) function")
    return sorted(set(bad))[:8]


_RUNNER = (
    "import sys, json, resource\n"
    "resource.setrlimit(resource.RLIMIT_CPU, (8, 8)); resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)\n"
    "resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)); resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16)); resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))\n"
    "d = json.load(sys.stdin); ns = {'__name__': 'tool'}\n"
    "exec(compile(d['code'], 'tool', 'exec'), ns)\n"
    "sys.stdout.write(json.dumps(ns['run'](d['payload']))[:20000])\n"
)

_PROBE = (
    "def run(p):\n import os, socket, json\n out = {'uid': os.getuid(), 'env': sorted(os.environ)}\n"
    " try:\n  s = socket.create_connection(('1.1.1.1', 53), 2); out['net'] = True\n except Exception: out['net'] = False\n"
    " for k, d in (('home', '/home'), ('root', '/root'), ('tmp', '/tmp')):\n  try: out[k] = len(os.listdir(d))\n  except Exception: out[k] = 0\n"
    " out['procs'] = len([x for x in os.listdir('/proc') if x.isdigit()])\n return out\n"
)


class Sandbox:
    """Wraps the isolated-execution mechanism and its mandatory
    self-test. One instance is enough for a whole process; `ready()`
    caches the self-test result."""

    def __init__(self):
        self._ok = None

    def _cmd(self):
        inner = (
            "mount -t tmpfs t /home && mount -t tmpfs t /root && mount -t tmpfs t /tmp && mount -t tmpfs t /var/tmp && "
            "exec env -i PATH=/usr/bin:/bin setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs %s -I -c %s"
            % (shlex.quote(sys.executable), shlex.quote(_RUNNER))
        )
        return ["sudo", "-n", "unshare", "--net", "--pid", "--ipc", "--uts", "--mount", "--fork", "--mount-proc", "sh", "-c", inner]

    def run_code(self, code, payload, timeout=10):
        """Runs `code` (must define run(payload)) inside the isolated
        sandbox only. Returns (ok, result_or_error_string). Refuses to
        run (returns False, "sandbox unavailable") unless `ready()` is
        True - there is intentionally no unisolated fallback path."""
        if not self.ready():
            return False, "sandbox unavailable (tools are disabled)"
        try:
            r = subprocess.run(
                self._cmd(),
                input=json.dumps({"code": code, "payload": payload}),
                capture_output=True, text=True, timeout=timeout,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except Exception as ex:
            return False, type(ex).__name__
        if r.returncode != 0:
            return False, (r.stderr or "failed")[-200:]
        try:
            return True, json.loads(r.stdout)
        except Exception:
            return False, "bad output"

    def ready(self):
        """Self-test: the sandbox must really cut the network, hide the
        host's files and drop privileges, or tools stay disabled.
        Result is cached after the first call."""
        if self._ok is not None:
            return self._ok
        self._ok = False  # fail closed while the probe runs
        ok, r = self.run_code(_PROBE, {}, 20)
        good = bool(
            ok and isinstance(r, dict)
            and r.get("uid") == 65534
            and set(r.get("env") or ["?"]) <= {"PATH", "LC_CTYPE", "LANG"}
            and r.get("net") is False
            and r.get("home") == 0 and r.get("root") == 0 and r.get("tmp") == 0
            and r.get("procs", 99) <= 3
        )
        self._ok = good
        print("sandbox self-test:", "OK" if good else "FAILED -> tools disabled", str(r)[:200], flush=True)
        return good

    def run_tool_file(self, path, payload, timeout=10):
        """Convenience: read a tool's source from `path` and run it."""
        try:
            code = open(path, encoding="utf-8").read()
        except Exception as ex:
            return False, type(ex).__name__
        return self.run_code(code, payload, timeout)
