"""CyGuide finding schemas and validation registries."""

from typing import Dict, List, Set

SUPPORTED_SCHEMAS: Dict[str, Dict[str, str]] = {
    "audit.misconfig": {
        "description": "A detected security misconfiguration, policy violation, or information exposure.",
        "pik": "target, check_id",
        "parent": "web.endpoint / network.service",
    },
    "credential.found": {
        "description": "A username/password or token discovery. Linked to a host or domain.",
        "pik": "context, username",
        "parent": "network.host",
    },
    "dns.record": {
        "description": "A single DNS entry mapping a name to a value.",
        "pik": "domain, type, value",
        "parent": "network.host",
    },
    "domain.info": {
        "description": "Whois registration data for a domain (owner, registrar, dates).",
        "pik": "domain",
        "parent": "None",
    },
    "entity.alias": {
        "description": "Links two identifiers that represent the same entity.",
        "pik": "source_id, target_id",
        "parent": "None",
    },
    "exploit.reference": {
        "description": "A known exploit or proof-of-concept reference from Exploit-DB or CVE archives.",
        "pik": "exploit_id",
        "parent": "vulnerability.found / network.service",
    },
    "file.system_object": {
        "description": "A file or directory found on a host.",
        "pik": "host_ip, path",
        "parent": "network.host",
    },
    "network.host": {
        "description": "A discovered machine on the network, identified by IP. Root entity for most scans.",
        "pik": "ip",
        "parent": "None",
    },
    "network.netblock": {
        "description": "An IP range with ownership data (org, ASN, CIDR).",
        "pik": "cidr",
        "parent": "None",
    },
    "network.service": {
        "description": "A listening port on a host.",
        "pik": "host_ip, port, protocol",
        "parent": "network.host",
    },
    "process.running": {
        "description": "A running process on a host.",
        "pik": "host_ip, pid",
        "parent": "network.host",
    },
    "software.package": {
        "description": "An installed software package.",
        "pik": "host_ip, package_name",
        "parent": "network.host",
    },
    "tls.certificate": {
        "description": "A TLS certificate associated with a service.",
        "pik": "fingerprint",
        "parent": "network.service",
    },
    "vulnerability.found": {
        "description": "A generic vulnerability linked to a host or service.",
        "pik": "host_ip, vuln_id",
        "parent": "network.service / network.host",
    },
    "web.endpoint": {
        "description": "A reachable HTTP/S URL with response metadata.",
        "pik": "url",
        "parent": "network.service",
    },
    "web.resource": {
        "description": "A specific asset (JS, CSS, Image) found on a web endpoint.",
        "pik": "url, resource_path",
        "parent": "web.endpoint",
    },
    "web.technology": {
        "description": "A detected web technology, framework, server, or CMS.",
        "pik": "url, technology_name",
        "parent": "web.endpoint / network.service",
    },
    "web.vulnerability": {
        "description": "A web-specific flaw (XSS, SQLi) found on an endpoint.",
        "pik": "url, vuln_type, parameter",
        "parent": "web.endpoint",
    },
}

SUPPORTED_WORDLISTS: Dict[str, str] = {
    "common_dirs": "Top web directories and files (raft / directory-list / common)",
    "subdomains_500": "High-frequency DNS subdomains",
    "common_params": "Frequent HTTP GET/POST parameter names",
    "common_usernames": "Standard administrative and service usernames",
    "common_passwords": "Default credentials and common passwords",
}

VALID_DIFFICULTIES: Set[str] = {"Beginner", "Intermediate", "Advanced"}

VALID_MACROS: Set[str] = {
    "{target}",
    "{url}",
    "{ip}",
    "{domain}",
    "{port}",
    "{cve_id}",
    "{wordlist}",
    "{wordlist:common_dirs}",
    "{wordlist:subdomains_500}",
    "{wordlist:common_params}",
    "{wordlist:common_usernames}",
    "{wordlist:common_passwords}",
}
