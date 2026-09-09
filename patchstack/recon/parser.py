from html.parser import HTMLParser
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urljoin, urlparse
from patchstack.recon.models import DiscoveredForm, FormField


class HTMLReconParser(HTMLParser):
    """
    HTML Parser for discovering links, forms, inputs, scripts, and meta tags.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.forms: List[DiscoveredForm] = []
        self.meta_tags: Dict[str, str] = {}

        self._current_form: Optional[DiscoveredForm] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        # Extract links
        if tag == "a" and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urljoin(self.base_url, href)
                self.links.append(full_url)

        # Extract scripts
        elif tag == "script" and "src" in attr_dict:
            src = attr_dict["src"].strip()
            if src:
                self.scripts.append(urljoin(self.base_url, src))

        # Extract meta tags
        elif tag == "meta":
            name = attr_dict.get("name") or attr_dict.get("property") or attr_dict.get("http-equiv")
            content = attr_dict.get("content")
            if name and content:
                self.meta_tags[name.lower()] = content

        # Extract forms
        elif tag == "form":
            action = attr_dict.get("action", "").strip()
            form_action = urljoin(self.base_url, action) if action else self.base_url
            method = attr_dict.get("method", "GET").upper()
            self._current_form = DiscoveredForm(
                action=form_action,
                method=method,
                fields=[],
                source_url=self.base_url,
            )

        # Extract form fields inside form tag
        elif tag in ("input", "textarea", "select", "button") and self._current_form is not None:
            field_name = attr_dict.get("name")
            if field_name:
                field_type = attr_dict.get("type", "text" if tag == "input" else tag)
                default_val = attr_dict.get("value", "")
                is_required = "required" in attr_dict
                self._current_form.fields.append(
                    FormField(
                        name=field_name,
                        field_type=field_type,
                        default_value=default_val,
                        required=is_required,
                    )
                )

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    @classmethod
    def parse_html(cls, html_content: str, base_url: str) -> Tuple[List[str], List[DiscoveredForm], List[str], Dict[str, str]]:
        parser = cls(base_url)
        try:
            parser.feed(html_content)
        except Exception:
            pass
        return parser.links, parser.forms, parser.scripts, parser.meta_tags
