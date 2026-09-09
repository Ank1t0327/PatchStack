from typing import Set, List, Dict, Tuple
from urllib.parse import urlparse, urljoin
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry
from patchstack.recon.models import DiscoveredEndpoint, DiscoveredForm
from patchstack.recon.parser import HTMLReconParser


class WebCrawler:
    """
    Recursive, domain-scoped HTTP crawler for target endpoint and form discovery.
    """

    def __init__(self, http_client: HTTPClient, max_depth: int = 2):
        self.http_client = http_client
        self.max_depth = max_depth

    def crawl(self, start_url: str) -> Tuple[List[DiscoveredEndpoint], List[DiscoveredForm], Dict[str, str], List[HTTPResponseTelemetry]]:
        parsed_target = urlparse(start_url)
        target_domain = parsed_target.netloc

        visited_urls: Set[str] = set()
        to_visit: List[Tuple[str, int]] = [(start_url, 0)]

        endpoints: List[DiscoveredEndpoint] = []
        all_forms: List[DiscoveredForm] = []
        all_cookies: Dict[str, str] = {}
        telemetry_history: List[HTTPResponseTelemetry] = []

        while to_visit:
            current_url, depth = to_visit.pop(0)

            # Normalize URL for deduplication
            normalized_url = current_url.split("#")[0]
            if normalized_url in visited_urls:
                continue

            visited_urls.add(normalized_url)

            # Enforce target domain scoping
            url_domain = urlparse(current_url).netloc
            if url_domain and url_domain != target_domain:
                continue

            telemetry = self.http_client.get(current_url)
            if not telemetry:
                continue

            telemetry_history.append(telemetry)
            all_cookies.update(telemetry.cookies)

            endpoint = DiscoveredEndpoint(
                url=telemetry.url,
                path=urlparse(telemetry.url).path or "/",
                method="GET",
                status_code=telemetry.status_code,
                content_type=telemetry.headers.get("Content-Type", "unknown").split(";")[0],
                depth=depth,
            )
            endpoints.append(endpoint)

            # If HTML response, parse links and forms
            if "html" in endpoint.content_type.lower() and telemetry.body:
                links, forms, _, _ = HTMLReconParser.parse_html(telemetry.body, telemetry.url)
                all_forms.extend(forms)

                if depth < self.max_depth:
                    for link in links:
                        link_domain = urlparse(link).netloc
                        link_norm = link.split("#")[0]
                        if (not link_domain or link_domain == target_domain) and link_norm not in visited_urls:
                            to_visit.append((link, depth + 1))

        # Deduplicate forms based on action and method
        unique_forms: List[DiscoveredForm] = []
        seen_forms: Set[Tuple[str, str]] = set()
        for form in all_forms:
            key = (form.action, form.method)
            if key not in seen_forms:
                seen_forms.add(key)
                unique_forms.append(form)

        return endpoints, unique_forms, all_cookies, telemetry_history
