import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logger
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# WHOIS server and not-found pattern config（参考 go 语言 config.go 完善）
WHOIS_SERVERS = {
    # Generic TLDs
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.nic.info",
    "biz": "whois.nic.biz",
    "mobi": "whois.nic.mobi",
    "edu": "whois.educause.edu",
    "gov": "whois.dotgov.gov",
    "mil": "whois.nic.mil",
    "int": "whois.iana.org",
    "ca": "whois.cira.ca",
    # Country and Region TLDs
    "cn": "whois.cnnic.cn",
    "hk": "whois.hkirc.hk",
    "tw": "whois.twnic.net.tw",
    # Popular New TLDs
    "io": "whois.nic.io",
    "ai": "whois.nic.ai",
    "me": "whois.nic.me",
    "cc": "whois.nic.cc",
    "tv": "whois.nic.tv",
    "co": "whois.nic.co",
    "xyz": "whois.nic.xyz",
    "top": "whois.nic.top",
    "vip": "whois.nic.vip",
    "club": "whois.nic.club",
    "shop": "whois.nic.shop",
    "site": "whois.nic.site",
    "wang": "whois.nic.wang",
    "xin": "whois.nic.xin",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "cloud": "whois.nic.cloud",
    "online": "whois.nic.online",
    "store": "whois.nic.store",
    # Chinese Regional TLDs
    "com.cn": "whois.cnnic.cn",
    "net.cn": "whois.cnnic.cn",
    "org.cn": "whois.cnnic.cn",
    "gov.cn": "whois.cnnic.cn",
    # Chinese IDN TLDs
    "中国": "whois.cnnic.cn",
    "公司": "whois.cnnic.cn",
    "网络": "whois.cnnic.cn",
    "商城": "whois.cnnic.cn",
    "网店": "whois.cnnic.cn",
    "中文网": "whois.cnnic.cn",
}

NOT_FOUND_PATTERNS = {
    "default": [
        "Domain not found",
        "No match for",
        "NOT FOUND",
        "No Data Found",
        "No entries found",
    ],
    "cn": ["no matching record", "No matching record"],
    "com": ["No match for", "NOT FOUND", "No Data Found"],
    "net": ["No match for", "NOT FOUND", "No Data Found"],
    # 可根据 go 版继续补充
}


def get_tld(domain):
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        compound = ".".join(parts[-2:])
        if compound in WHOIS_SERVERS:
            return compound
        return parts[-1]
    return domain


def query_whois(domain, timeout=5):
    tld = get_tld(domain)
    whois_server = WHOIS_SERVERS.get(tld, "whois.iana.org")
    logger.debug(f"Querying WHOIS for {domain} at {whois_server}")
    try:
        with socket.create_connection((whois_server, 43), timeout=timeout) as sock:
            sock.sendall((domain + "\r\n").encode())
            sock.settimeout(timeout)
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
        return response.decode(errors="ignore")
    except Exception as e:
        logger.warning(f"WHOIS query failed for {domain}: {e}")
        return ""


def is_domain_available(domain, whois_response):
    tld = get_tld(domain)
    patterns = NOT_FOUND_PATTERNS.get(tld, []) + NOT_FOUND_PATTERNS.get("default", [])
    for pattern in patterns:
        if pattern.lower() in whois_response.lower():
            return True
    return False


def check_domain_availability(domain):
    """
    Fast WHOIS check: only minimal query and pattern match, no full parsing.
    """
    logger.info(f"Checking domain: {domain}")
    whois_response = query_whois(domain)
    if whois_response:
        if is_domain_available(domain, whois_response):
            logger.info(f"{domain} is available (WHOIS)")
            return "available"
        else:
            logger.info(f"{domain} is registered (WHOIS)")
            return "registered"
    # WHOIS 查询失败，尝试 DNS 兜底
    try:
        socket.getaddrinfo(domain, None, timeout=5)
        logger.info(f"{domain} is registered (DNS fallback)")
        return "registered"
    except Exception:
        logger.info(f"{domain} is available (DNS fallback)")
        return "available"


def check_domains_availability(domain_names: list[str]) -> dict[str, str]:
    """
    Check the availability of multiple domains in batch, using up to 10 concurrent threads.
    Args:
        domain_names: A list of domain names to check.
    Returns:
        A dictionary where keys are domain names and values are their status
        ("available" or "registered").
    """
    results = {}
    logger.info(
        f"Starting batch check for {len(domain_names)} domains (max 10 concurrent threads)..."
    )
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_domain = {
            executor.submit(check_domain_availability, domain): domain
            for domain in domain_names
        }
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                results[domain] = future.result()
            except Exception as e:
                logger.error(f"Error checking {domain}: {e}", exc_info=True)
                results[domain] = f"error: {e}"
    logger.info("Batch check completed.")
    return results
