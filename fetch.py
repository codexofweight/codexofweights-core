"""codexofweights-core: generic web/feed fetch helpers.

Transplanted (the reusable half) from
codexofweights_agent/part_04_research.py. The agent-specific part of
that file - deciding WHICH feeds to read, scoring candidates against
the agent's own interests, and writing gists into its private memory -
stays in the agent. What is generic and worth sharing is just: fetch a
URL safely, strip HTML to plain text, and parse an RSS/Atom feed
defensively.

Security note: `parse_feed` rejects any `<!ENTITY` declaration before
parsing. Without this, a malicious feed could define an entity that
expands into something huge (a "billion laughs" denial-of-service) or
that resolves a local/network path (XXE), while LOOKING like an
ordinary RSS item. Treat every feed as adversarial input, because it
is - it's fetched from arbitrary third-party URLs.
"""
import re
import urllib.request
import xml.etree.ElementTree as ET


def web_get(url, timeout=20, user_agent=None, max_bytes=2_000_000):
    """Fetch a URL as text. Caps the read at `max_bytes` so one huge or
    hostile response can't exhaust memory. Returns "" on any failure -
    callers should treat empty string as "could not fetch", not as an
    empty-but-valid page."""
    req = urllib.request.Request(url, headers={"User-Agent": user_agent or "codexofweights-core/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(max_bytes + 1)
    except Exception:
        return ""
    if len(data) > max_bytes:
        data = data[:max_bytes]
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return ""


def plain(html, max_len=4000):
    """Strip tags/scripts/styles from HTML and collapse whitespace,
    for feeding page text to an LLM without markup noise."""
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html or "")
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len]


def parse_feed(xml_text, max_items=30):
    """Parse an RSS or Atom feed into a list of
    {"title", "link", "summary"} dicts. Refuses (returns []) if the
    feed declares a custom XML entity - a defense against entity-
    expansion and XXE attacks from untrusted feed URLs. Any other
    parse failure also returns [] rather than raising, since a broken
    feed should not crash the caller."""
    if "<!ENTITY" in xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return []
    items = []
    tag = root.tag.lower()
    if tag.endswith("feed"):  # Atom
        ns = {"a": "http://www.w3.org/2005/Atom"}
        for entry in root.findall("a:entry", ns)[:max_items]:
            title = (entry.findtext("a:title", default="", namespaces=ns) or "").strip()
            link_el = entry.find("a:link", ns)
            link = link_el.get("href", "") if link_el is not None else ""
            summary = (entry.findtext("a:summary", default="", namespaces=ns)
                       or entry.findtext("a:content", default="", namespaces=ns) or "")
            items.append({"title": title, "link": link, "summary": plain(summary, 600)})
    else:  # RSS
        for item in root.findall(".//item")[:max_items]:
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            summary = item.findtext("description") or ""
            items.append({"title": title, "link": link, "summary": plain(summary, 600)})
    return items
