"""
Bug Bounty Mode Configuration.

Pre-configured settings for popular bug bounty programs.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BugBountyConfig:
    """Configuration for a specific bug bounty program."""
    name: str
    platform: str  # hackerone, bugcrowd, etc.
    user_agent_suffix: str = ""
    rate_limit: int = 10  # requests per second
    required_headers: Dict[str, str] = field(default_factory=dict)
    in_scope_domains: List[str] = field(default_factory=list)
    out_of_scope_patterns: List[str] = field(default_factory=list)
    notes: str = ""


# Pre-configured bug bounty programs
BOUNTY_PROGRAMS: Dict[str, BugBountyConfig] = {
    "inditex": BugBountyConfig(
        name="Inditex (Zara, Bershka, etc.)",
        platform="hackerone",
        user_agent_suffix="-inSec-CrowdPowered",
        rate_limit=5,
        in_scope_domains=[
            "www.zara.com",
            "www.bershka.com",
            "www.pullandbear.com",
            "www.stradivarius.com",
            "www.oysho.com",
            "www.zarahome.com",
            "www.massimodutti.com",
            "www.lefties.com",
        ],
        notes="Must use own accounts only. No DoS testing.",
    ),
    "notion": BugBountyConfig(
        name="Notion Labs",
        platform="hackerone",
        rate_limit=10,
        in_scope_domains=[
            "www.notion.so",
            "notion.so",
            "api.notion.com",
        ],
        notes="Interested in IDOR and privilege escalation.",
    ),
    "doordash": BugBountyConfig(
        name="DoorDash",
        platform="hackerone",
        rate_limit=10,
        in_scope_domains=[
            "www.doordash.com",
            "doordash.com",
        ],
        notes="High rewards for PII exposure.",
    ),
    "tinder": BugBountyConfig(
        name="Tinder",
        platform="hackerone",
        rate_limit=5,
        in_scope_domains=[
            "tinder.com",
            "api.gotinder.com",
        ],
        notes="High bounty floor ($500). Sensitive user data.",
    ),
    "nextcloud": BugBountyConfig(
        name="Nextcloud",
        platform="hackerone",
        rate_limit=10,
        in_scope_domains=[
            "nextcloud.com",
        ],
        notes="Focus on file sharing ACL logic.",
    ),
}


def get_bounty_config(program_name: str) -> Optional[BugBountyConfig]:
    """
    Get configuration for a specific bug bounty program.
    
    Args:
        program_name: Name of the program (case-insensitive)
        
    Returns:
        BugBountyConfig if found, None otherwise
    """
    return BOUNTY_PROGRAMS.get(program_name.lower())


def list_programs() -> List[str]:
    """List all available bug bounty program configurations."""
    return list(BOUNTY_PROGRAMS.keys())


def get_user_agent(program_name: str, base_ua: str = "") -> str:
    """
    Get the required User-Agent for a bug bounty program.
    
    Args:
        program_name: Name of the program
        base_ua: Base User-Agent string
        
    Returns:
        User-Agent string with required suffix
    """
    config = get_bounty_config(program_name)
    if config and config.user_agent_suffix:
        return f"{base_ua} {config.user_agent_suffix}".strip()
    return base_ua


def is_in_scope(program_name: str, domain: str) -> bool:
    """
    Check if a domain is in scope for a bug bounty program.
    
    Args:
        program_name: Name of the program
        domain: Domain to check
        
    Returns:
        True if in scope, False otherwise
    """
    config = get_bounty_config(program_name)
    if not config:
        return True  # No config means we can't validate
    
    domain = domain.lower()
    for scope_domain in config.in_scope_domains:
        if domain == scope_domain or domain.endswith(f".{scope_domain}"):
            return True
    
    return False
