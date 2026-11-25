import re
from urllib.parse import urlparse, urlunparse

def normalize_url(url: str) -> str:

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("URL contains invalid control characters.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ["http", "https"]:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL: hostname is missing.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not supported.")

    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower()
    )

    return urlunparse(normalized)

def extract_url_components(url: str) -> dict:

    parsed = urlparse(url)

    return {
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "port": parsed.port
    }

def detect_suspicious_patterns(url: str) -> list:

    findings = []

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path.lower()
    full_url = url.lower()

    # Check for IP address instead of domain name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        findings.append({
            "title": "IP Address Used as Hostname",
            "description": "The URL uses an IP address instead of a domain name.",
            "severity": "medium"
        })

    # Check for suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "account",
        "password",
        "secure",
        "update",
        "banking"
    ]

    for keyword in suspicious_keywords:
        if keyword in path:
            findings.append({
                "title": "Sensitive Keyword in URL",
                "description": f"The URL path contains the keyword '{keyword}'. This deserves closer inspection.",
                "severity": "low"
            })

    # Check for excessive subdomains
    if len(hostname.split(".")) > 4:
        findings.append({
            "title": "Excessive Subdomains",
            "description": "The hostname contains an unusually large number of subdomains.",
            "severity": "medium"
        })

    # Check for URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly"
    ]

    if any(hostname == domain or hostname.endswith("." + domain) for domain in shorteners):
        findings.append({
            "title": "URL Shortener Detected",
            "description": "The URL uses a shortening service that hides the final destination.",
            "severity": "medium"
        })

    # Check for @ symbol
    if "@" in parsed.netloc:
        findings.append({
            "title": "At Symbol in URL",
            "description": "The URL contains an @ symbol in its network location.",
            "severity": "high"
        })

    return findings

def detect_url_obfuscation(url: str) -> list:

    findings = []

    parsed = urlparse(url)

    # Check for hexadecimal or percent encoding
    if re.search(r"%[0-9a-fA-F]{2}", url):
        findings.append({
            "title": "Encoded Characters Detected",
            "description": "The URL contains percent-encoded characters that may hide parts of its structure.",
            "severity": "low"
        })

    # Check for unusually long URLs
    if len(url) > 200:
        findings.append({
            "title": "Unusually Long URL",
            "description": "The URL is unusually long and may contain hidden or unnecessary parameters.",
            "severity": "medium"
        })

    # Check for multiple subdomains
    hostname = parsed.hostname or ""

    if len(hostname.split(".")) >= 5:
        findings.append({
            "title": "Complex Hostname Structure",
            "description": "The hostname contains multiple subdomain levels and deserves closer inspection.",
            "severity": "medium"
        })

    return findings

def detect_suspicious_domain(url: str) -> list:

    findings = []

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    # Check for excessive hyphens
    if hostname.count("-") >= 3:
        findings.append({
            "title": "Excessive Hyphens in Domain",
            "description": "The domain contains several hyphens, which can be used in deceptive domain names.",
            "severity": "low"
        })

    # Check for suspicious brand-like keywords
    brand_keywords = [
        "paypal",
        "google",
        "microsoft",
        "amazon",
        "apple",
        "facebook",
        "instagram"
    ]

    domain_parts = hostname.split(".")

    for keyword in brand_keywords:
        if keyword in hostname and not any(
            part == keyword for part in domain_parts
        ):
            findings.append({
                "title": "Possible Brand Impersonation",
                "description": f"The hostname contains '{keyword}' without using it as a separate domain label.",
                "severity": "medium"
            })

    return findings

def detect_insecure_connection(url: str) -> list:

    findings = []

    parsed = urlparse(url)

    if parsed.scheme.lower() == "http":
        findings.append({
            "title": "Insecure HTTP Connection",
            "description": "The URL uses HTTP instead of HTTPS. Communication with the website is not protected by TLS encryption.",
            "severity": "medium"
        })

    return findings

def analyze_url(url: str) -> dict:

    normalized_url = normalize_url(url)

    components = extract_url_components(normalized_url)

    findings = []

    findings.extend(detect_suspicious_patterns(normalized_url))
    findings.extend(detect_url_obfuscation(normalized_url))
    findings.extend(detect_suspicious_domain(normalized_url))
    findings.extend(detect_insecure_connection(normalized_url))

    risk = calculate_risk_score(findings)

    return {
        "normalized_url": normalized_url,
        "components": components,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "findings": findings
    }


def calculate_risk_score(findings: list) -> dict:

    score = 0

    severity_points = {
        "low": 5,
        "medium": 15,
        "high": 30,
        "critical": 50
    }

    for finding in findings:
        score += severity_points.get(
            finding["severity"],
            0
        )

    score = min(score, 100)

    if score == 0:
        risk_level = "low_risk"

    elif score <= 20:
        risk_level = "low_risk"

    elif score <= 40:
        risk_level = "suspicious"

    else:
        risk_level = "high_risk"

    return {
        "risk_score": score,
        "risk_level": risk_level
    }