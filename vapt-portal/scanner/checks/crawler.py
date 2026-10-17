"""Lightweight same-origin crawler.

Discovers in-scope URLs, query parameters and HTML forms so the active PT
probes have a real attack surface to test (not just the home page). It only
issues GET requests and parses returned HTML; it never submits forms or sends
payloads. Bounded by page/-depth limits so it stays polite.
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlsplit, parse_qs

import requests

UA = "Tech Guardians-VAPT/3.0 (authorised security assessment)"

_LINK_RE = re.compile(r'(?:href|action)=["\']([^"\'#]+)["\']', re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
_ACTION_RE = re.compile(r'action=["\']([^"\']*)["\']', re.I)
_METHOD_RE = re.compile(r'method=["\']([^"\']*)["\']', re.I)
_INPUT_RE = re.compile(r'<(?:input|textarea|select)\b[^>]*name=["\']([^"\']+)["\']',
                       re.I)


def crawl(base_url: str, result, max_pages: int = 40, max_depth: int = 2,
          timeout: int = 12) -> dict:
    """Return {'urls':[...], 'get_params':[{url,params}], 'forms':[{...}]}."""
    result.mark_check("Crawl / attack-surface discovery")
    host = urlparse(base_url).hostname
    session = requests.Session()
    session.headers.update({"User-Agent": UA})

    seen: set[str] = set()
    urls: list[str] = []
    get_params: list[dict] = []
    forms: list[dict] = []
    seen_param_sigs: set[str] = set()
    seen_form_sigs: set[str] = set()

    queue: deque[tuple[str, int]] = deque([(base_url, 0)])
    pages = 0

    while queue and pages < max_pages:
        url, depth = queue.popleft()
        key = url.split("#")[0]
        if key in seen or depth > max_depth:
            continue
        seen.add(key)
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True,
                               verify=True)
        except Exception:  # noqa: BLE001
            continue
        pages += 1
        urls.append(resp.url)
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype.lower():
            continue
        html = resp.text or ""

        # Record query parameters on this URL.
        qs = parse_qs(urlsplit(resp.url).query)
        if qs:
            sig = urlsplit(resp.url).path + "?" + ",".join(sorted(qs))
            if sig not in seen_param_sigs:
                seen_param_sigs.add(sig)
                get_params.append({"url": resp.url,
                                   "params": {k: v[0] for k, v in qs.items()}})

        # Parse forms.
        for fblock in _FORM_RE.findall(html):
            action = (_ACTION_RE.search(fblock) or [None, ""])
            action_url = urljoin(resp.url, action.group(1) if action else "")
            if urlparse(action_url).hostname != host:
                continue
            method = "post" if (_METHOD_RE.search(fblock) and
                                _METHOD_RE.search(fblock).group(1).lower() == "post") \
                else "get"
            inputs = sorted(set(_INPUT_RE.findall(fblock)))
            if not inputs:
                continue
            fsig = f"{method}:{action_url}:{','.join(inputs)}"
            if fsig not in seen_form_sigs:
                seen_form_sigs.add(fsig)
                forms.append({"action": action_url, "method": method,
                             "inputs": inputs})

        # Enqueue same-origin links.
        if depth < max_depth:
            for href in _LINK_RE.findall(html):
                nxt = urljoin(resp.url, href)
                if urlparse(nxt).hostname == host and nxt.split("#")[0] not in seen:
                    # collect params even if we don't re-crawl everything
                    q = parse_qs(urlsplit(nxt).query)
                    if q:
                        sig = urlsplit(nxt).path + "?" + ",".join(sorted(q))
                        if sig not in seen_param_sigs:
                            seen_param_sigs.add(sig)
                            get_params.append(
                                {"url": nxt,
                                 "params": {k: v[0] for k, v in q.items()}})
                    queue.append((nxt, depth + 1))

    surface = {"urls": urls, "get_params": get_params, "forms": forms}
    result.meta["attack_surface"] = {
        "pages_crawled": pages,
        "urls": len(urls),
        "parameterised_urls": len(get_params),
        "forms": len(forms),
    }
    result.log(f"Crawl complete: {pages} pages, {len(get_params)} param URLs, "
               f"{len(forms)} forms")
    return surface
