import argparse
import json
import re
import socket
from urllib.parse import urljoin, urlparse

import requests 
from bs4 import BeautifulSoup


# ============================================================
# WEB RECON
# Passive / low-impact reconnaissance tool
# ============================================================

TIMEOUT = 30

session = requests.Session()

session.headers.update({
    "User-Agent": "WebRecon/1.0"
})


# ============================================================
# UI
# ============================================================

def banner():
    print(r"""
╔══════════════════════════════════════════════════════╗
║                  PYTHON WEB RECON                    ║
║             Passive Reconnaissance Tool             ║
╚══════════════════════════════════════════════════════╝
""")


def section(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)


# ============================================================
# URL
# ============================================================

def normalize_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url.rstrip("/")


# ============================================================
# HTTP
# ============================================================

def fetch(url):

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        return response

    except requests.RequestException as error:

        print(f"[!] Request error: {error}")
        return None


# ============================================================
# IP ADDRESS
# ============================================================

def resolve_ip(domain):

    section("IP ADDRESS")

    addresses = set()

    try:

        results = socket.getaddrinfo(
            domain,
            None
        )

        for result in results:

            ip = result[4][0]

            addresses.add(ip)

        if addresses:

            for ip in sorted(addresses):
                print(f"[+] {ip}")

        else:

            print("[!] No IP address found.")

    except socket.gaierror as error:

        print(f"[!] DNS resolution failed: {error}")

    return sorted(addresses)


# ============================================================
# SUBDOMAINS
# ============================================================

def find_subdomains(domain):

    section("PUBLIC SUBDOMAINS")

    url = (
        "https://crt.sh/"
        f"?q=%25.{domain}"
        "&output=json"
    )

    subdomains = set()

    try:

        response = session.get(
            url,
            timeout=TIMEOUT
        )

        if response.status_code != 200:

            print(
                f"[!] Certificate Transparency request "
                f"returned HTTP {response.status_code}"
            )

            return []

        data = response.json()

        for certificate in data:

            names = certificate.get(
                "name_value",
                ""
            )

            for name in names.splitlines():

                name = name.strip().lower()

                name = name.lstrip("*.")

                if (
                    name == domain
                    or name.endswith("." + domain)
                ):

                    subdomains.add(name)

        if subdomains:

            for subdomain in sorted(subdomains):
                print(f"[+] {subdomain}")

        else:

            print("[!] No public subdomains found.")

    except Exception as error:

        print(f"[!] Subdomain lookup failed: {error}")

    return sorted(subdomains)


# ============================================================
# DNS INFORMATION
# ============================================================

def dns_information(domain):

    section("DNS INFORMATION")

    results = {}

    try:

        hostname, aliases, addresses = socket.gethostbyname_ex(
            domain
        )

        results["hostname"] = hostname
        results["aliases"] = aliases
        results["addresses"] = addresses

        print(f"Hostname: {hostname}")

        if aliases:

            print("\nAliases:")

            for alias in aliases:
                print(f"  → {alias}")

        if addresses:

            print("\nAddresses:")

            for address in addresses:
                print(f"  → {address}")

    except socket.gaierror:

        print("[!] Could not resolve DNS information.")

    return results


# ============================================================
# SERVER INFORMATION
# ============================================================

def server_information(response):

    section("SERVER INFORMATION")

    interesting_headers = [
        "Server",
        "X-Powered-By",
        "Via",
        "X-Generator",
        "X-Server",
        "X-AspNet-Version",
        "X-AspNetMvc-Version"
    ]

    results = {}

    for header in interesting_headers:

        value = response.headers.get(header)

        if value:

            print(f"[+] {header}: {value}")

            results[header] = value

    if not results:

        print("[!] No obvious server information exposed.")

    return results


# ============================================================
# TECHNOLOGY DETECTION
# ============================================================

def detect_technologies(response):

    section("TECHNOLOGIES")

    html = response.text.lower()

    technologies = set()

    indicators = {

        "WordPress": [
            "wp-content",
            "wp-includes",
            "wordpress"
        ],

        "React": [
            "react",
            "__react"
        ],

        "Next.js": [
            "__next_data__",
            "_next/static"
        ],

        "Vue.js": [
            "vue.js",
            "vue@"
        ],

        "Angular": [
            "ng-version",
            "angular"
        ],

        "Bootstrap": [
            "bootstrap.min.css",
            "bootstrap.min.js"
        ],

        "Tailwind CSS": [
            "tailwindcss"
        ],

        "jQuery": [
            "jquery",
            "jquery.min.js"
        ],

        "PHP": [
            ".php"
        ],

        "Laravel": [
            "laravel"
        ],

        "Django": [
            "csrfmiddlewaretoken",
            "django"
        ],

        "Flask": [
            "flask"
        ],

        "ASP.NET": [
            "asp.net",
            "__viewstate"
        ],

        "Node.js": [
            "express",
            "node.js"
        ]
    }

    for technology, signatures in indicators.items():

        for signature in signatures:

            if signature in html:

                technologies.add(technology)

                print(f"[+] {technology}")

                break

    # Server header can provide another clue
    server = response.headers.get(
        "Server",
        ""
    ).lower()

    powered = response.headers.get(
        "X-Powered-By",
        ""
    ).lower()

    if "nginx" in server:
        technologies.add("Nginx")
        print("[+] Nginx")

    if "apache" in server:
        technologies.add("Apache")
        print("[+] Apache")

    if "php" in powered:
        technologies.add("PHP")
        print("[+] PHP")

    if "express" in powered:
        technologies.add("Express.js")
        print("[+] Express.js")

    if not technologies:

        print("[!] No obvious technology indicators found.")

    return sorted(technologies)


# ============================================================
# HTML LINKS
# ============================================================

def discover_links(base_url, response):

    section("WEBSITE URLS")

    soup = BeautifulSoup(
        response.text,
        "html.parser"
    )

    base_domain = urlparse(
        base_url
    ).netloc

    internal = set()
    external = set()

    for tag in soup.find_all(
        "a",
        href=True
    ):

        href = tag["href"].strip() # type: ignore

        if href.startswith(
            ("javascript:", "mailto:", "tel:")
        ):
            continue

        link = urljoin(
            base_url,
            href
        )

        parsed = urlparse(link)

        if parsed.scheme not in (
            "http",
            "https"
        ):
            continue

        clean_link = link.split("#")[0]

        if parsed.netloc == base_domain:

            internal.add(clean_link)

        else:

            external.add(clean_link)

    print("\nInternal URLs:")

    for link in sorted(internal):

        print(f"  → {link}")

    print("\nExternal domains:")

    external_domains = set()

    for link in external:

        domain = urlparse(
            link
        ).netloc

        if domain:
            external_domains.add(domain)

    for domain in sorted(external_domains):

        print(f"  → {domain}")

    print(
        f"\n[+] Internal URLs: {len(internal)}"
    )

    print(
        f"[+] External domains: "
        f"{len(external_domains)}"
    )

    return {
        "internal_urls": sorted(internal),
        "external_domains": sorted(external_domains)
    }


# ============================================================
# JAVASCRIPT
# ============================================================

def find_javascript(response):

    section("JAVASCRIPT FILES")

    soup = BeautifulSoup(
        response.text,
        "html.parser"
    )

    scripts = set()

    for script in soup.find_all(
        "script",
        src=True
    ):

        scripts.add(
            script["src"]
        )

    for script in sorted(scripts):

        print(f"  → {script}")

    print(
        f"\n[+] JavaScript files: {len(scripts)}"
    )

    return sorted(scripts)


# ============================================================
# ROBOTS
# ============================================================

def get_robots(base_url):
    section("ROBOTS.TXT")

    robots_url = urljoin(base_url + "/", "robots.txt")
    response = fetch(robots_url)

    if not response:
        return None

    if response.status_code == 200:
        print(f"[+] {robots_url}")
        print()
        print(response.text[:5000])

        # Save robots.txt to the project folder
        filename = "robots.txt_report.txt"

        try:
            with open(filename, "w", encoding="utf-8") as file:
                file.write(response.text)

            print(f"\n[+] robots.txt saved as: {filename}")

        except OSError as error:
            print(f"[!] Could not save robots.txt: {error}")

        return response.text

    print(f"[!] robots.txt returned HTTP {response.status_code}")
    return None

      

# ============================================================
# SITEMAP
# ============================================================

def get_sitemap(base_url):

    section("SITEMAP")

    sitemap_url = urljoin(
        base_url + "/",
        "sitemap.xml"
    )

    response = fetch(
        sitemap_url
    )

    if not response:

        return []

    if response.status_code != 200:

        print("[!] sitemap.xml not found.")

        return []

    urls = re.findall(
        r"<loc>\s*(.*?)\s*</loc>",
        response.text,
        re.IGNORECASE
    )

    for url in urls:

        print(f"  → {url}")

    print(
        f"\n[+] Sitemap URLs: {len(urls)}"
    )

    return urls


# ============================================================
# HTTP HEADERS
# ============================================================

def get_headers(response):

    section("HTTP RESPONSE HEADERS")

    headers = {}

    for key, value in response.headers.items():

        print(
            f"{key}: {value}"
        )

        headers[key] = value

    return headers


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Passive Web Reconnaissance Tool"
        )
    )

    parser.add_argument(
        "url",
        help="Website URL"
    )

    parser.add_argument(
        "--output",
        default="recon_report.json",
        help="JSON report filename"
    )

    args = parser.parse_args()

    url = normalize_url(
        args.url
    )

    banner()

    print(
        f"Target: {url}"
    )

    print(
        "\n[!] Use only on systems you own "
        "or are authorized to assess."
    )

    # --------------------------------------------------------
    # Initial request
    # --------------------------------------------------------

    response = fetch(url)

    if not response:

        print(
            "\n[!] Unable to connect to target."
        )

        return

    parsed = urlparse(
        response.url
    )

    domain = parsed.hostname

    # --------------------------------------------------------
    # Basic information
    # --------------------------------------------------------

    section("TARGET INFORMATION")

    print(
        f"Original URL : {url}"
    )

    print(
        f"Final URL    : {response.url}"
    )

    print(
        f"Domain       : {domain}"
    )

    print(
        f"Protocol     : {parsed.scheme}"
    )

    print(
        f"HTTP Status  : {response.status_code}"
    )

    # --------------------------------------------------------
    # Recon
    # --------------------------------------------------------

    ips = resolve_ip(
        domain
    )

    dns = dns_information(
        domain
    )

    subdomains = find_subdomains(
        domain
    )

    server = server_information(
        response
    )

    technologies = detect_technologies(
        response
    )

    links = discover_links(
        url,
        response
    )

    javascript = find_javascript(
        response
    )

    robots = get_robots(
        url
    )

    sitemap = get_sitemap(
        url
    )

    headers = get_headers(
        response
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    section("RECON SUMMARY")

    print(
        f"Target          : {domain}"
    )

    print(
        f"IP addresses    : {len(ips)}"
    )

    print(
        f"Subdomains      : {len(subdomains)}"
    )

    print(
        f"Internal URLs   : "
        f"{len(links['internal_urls'])}"
    )

    print(
        f"External domains: "
        f"{len(links['external_domains'])}"
    )

    print(
        f"Technologies    : "
        f"{len(technologies)}"
    )

    print(
        f"JavaScript      : "
        f"{len(javascript)}"
    )

    print(
        f"Server headers  : "
        f"{len(server)}"
    )

    # --------------------------------------------------------
    # JSON report
    # --------------------------------------------------------

    report = {

        "target": {
            "url": url,
            "final_url": response.url,
            "domain": domain,
            "protocol": parsed.scheme,
            "status": response.status_code
        },

        "ip_addresses": ips,

        "dns": dns,

        "subdomains": subdomains,

        "server_information": server,

        "technologies": technologies,

        "website_urls": links,

        "javascript_files": javascript,

        "robots_txt": robots,

        "sitemap": sitemap,

        "http_headers": headers
    }

    try:

        with open(
            args.output,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4
            )

        print(
            f"\n[+] Report saved: "
            f"{args.output}"
        )

    except OSError as error:

        print(
            f"[!] Could not save report: {error}"
        )


if __name__ == "__main__":
    main()