"""Validate the small, self-contained GitHub Pages publishing directory."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

SITE = Path(__file__).resolve().parents[1] / "site"
EXPECTED_FILES = {"index.html", "styles.css", "app.js", "assets/mark.svg", ".nojekyll"}


class SiteParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.links: list[str] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        names = [name for name, _ in attrs]
        if len(names) != len(set(names)):
            self.errors.append(f"Element <{tag}> contains a duplicate attribute")
        attributes = dict(attrs)
        element_id = attributes.get("id")
        if element_id:
            if element_id in self.ids:
                self.errors.append(f"Duplicate ID: {element_id}")
            self.ids.add(element_id)
        for key in ("href", "src"):
            value = attributes.get(key)
            if value:
                self.links.append(value)
        if tag == "img" and "alt" not in attributes:
            self.errors.append("Image is missing an alt attribute")
        if tag == "button" and attributes.get("type") != "button":
            self.errors.append("Button must declare type='button'")


def main() -> int:
    actual = {path.relative_to(SITE).as_posix() for path in SITE.rglob("*") if path.is_file()}
    errors = []
    if actual != EXPECTED_FILES:
        errors.append(f"Unexpected publishing file set: {sorted(actual ^ EXPECTED_FILES)}")
    if any(path.is_symlink() for path in SITE.rglob("*")):
        errors.append("Publishing directory must not contain symbolic links")
    parser = SiteParser()
    parser.feed((SITE / "index.html").read_text(encoding="utf-8"))
    errors.extend(parser.errors)
    for link in parser.links:
        parsed = urlsplit(link)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme != "https":
                errors.append(f"External URL must use HTTPS: {link}")
            continue
        if parsed.path.startswith("/"):
            errors.append(f"Use relative assets for the /mendpact/ Pages base path: {link}")
        target = (SITE / unquote(parsed.path)).resolve() if parsed.path else SITE / "index.html"
        if not target.is_relative_to(SITE) or not target.is_file():
            errors.append(f"Local link is missing or outside site/: {link}")
        if parsed.fragment and target == SITE / "index.html" and parsed.fragment not in parser.ids:
            errors.append(f"Unknown page anchor: {link}")
    for error in errors:
        print(error)
    if errors:
        return 1
    print(f"Website validated: {len(actual)} publishing files; local links and anchors resolve.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
