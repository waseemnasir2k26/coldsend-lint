"""Parse a campaign message file into headers + subject + body.

Accepts two shapes:

1. RFC-822-ish: header lines (``Subject:``, ``From:`` ...), a blank line, body.
2. Body only: no recognised header block, the whole file is the body.

HTML bodies are kept verbatim; a text projection with tags stripped is exposed
as ``text`` so the copy rules match on words rather than markup.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9\-]*):[ \t]*(.*)$")
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_MAILTO_RE = re.compile(r"mailto:[^\s\"'<>)\]]+", re.IGNORECASE)
_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_IMG_RE = re.compile(r"<img\b", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_IMAGE_URL_RE = re.compile(r"https?://\S+\.(?:png|jpe?g|gif|webp)\b", re.IGNORECASE)

# Known-inert destinations people ship by accident.
_PLACEHOLDER_LINK_RE = re.compile(
    r"""(^\#$)|(^javascript:)|(\{\{[^}]*\}\})|(\[\[[^\]]*\]\])|(%%[A-Z_]+%%)"""
    r"""|(example\.(com|org|net))|(your-?domain)|(TODO)|(INSERT_)""",
    re.IGNORECASE,
)


@dataclass
class Message:
    raw: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    path: str = "<stdin>"

    @property
    def subject(self) -> str:
        return self.headers.get("subject", "")

    @property
    def sender(self) -> str:
        return self.headers.get("from", "")

    @property
    def is_html(self) -> bool:
        return bool(re.search(r"<(html|body|table|div|p|a|img)\b", self.body, re.I))

    @property
    def text(self) -> str:
        """Body with HTML tags removed and entities lightly normalised."""
        if not self.is_html:
            return self.body
        stripped = _TAG_RE.sub(" ", self.body)
        stripped = stripped.replace("&nbsp;", " ").replace("&amp;", "&")
        return re.sub(r"[ \t]{2,}", " ", stripped)

    @property
    def searchable(self) -> str:
        """Subject + text body, what most legal rules should look at."""
        return f"{self.subject}\n{self.text}"

    def links(self) -> list[str]:
        found = _HREF_RE.findall(self.body)
        found += _URL_RE.findall(self.text if self.is_html else self.body)
        found += _MAILTO_RE.findall(self.body)
        seen: list[str] = []
        for link in found:
            if link not in seen:
                seen.append(link)
        return seen

    def image_count(self) -> int:
        """<img> tags plus bare image URLs, counting each image once.

        A URL inside an ``<img src="...">`` must not be counted twice, so bare
        image URLs are looked for in the tag-stripped projection only.
        """
        return len(_IMG_RE.findall(self.body)) + len(_IMAGE_URL_RE.findall(self.text))

    def text_length(self) -> int:
        return len(re.sub(r"\s+", " ", self.text).strip())


def is_placeholder_link(link: str) -> bool:
    return bool(_PLACEHOLDER_LINK_RE.search(link.strip()))


def parse_message(raw: str, path: str = "<stdin>") -> Message:
    lines = raw.splitlines()
    headers: dict[str, str] = {}
    body_start = 0

    # A header block only counts if the FIRST line is a header and a blank line
    # closes the block. Otherwise treat the whole file as body.
    if lines and _HEADER_RE.match(lines[0]):
        last_key: str | None = None
        for i, line in enumerate(lines):
            if line.strip() == "":
                body_start = i + 1
                break
            match = _HEADER_RE.match(line)
            if match:
                last_key = match.group(1).lower()
                headers[last_key] = match.group(2).strip()
            elif line[:1] in (" ", "\t") and last_key:
                headers[last_key] += " " + line.strip()
            else:  # not a header block after all
                headers = {}
                body_start = 0
                break
        else:
            body_start = len(lines)

    return Message(
        raw=raw,
        headers=headers,
        body="\n".join(lines[body_start:]).strip("\n"),
        path=path,
    )


def load_message(path: str | Path) -> Message:
    p = Path(path)
    return parse_message(p.read_text(encoding="utf-8"), str(p))
