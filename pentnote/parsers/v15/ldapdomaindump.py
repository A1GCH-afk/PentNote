"""LDAPDomainDump parser."""

from __future__ import annotations

import json
from typing import Any

from pentnote.models import DomainObject, ParsedResult
from pentnote.parsers.base import AbstractParser


class LDAPDomainDumpParser(AbstractParser):
    """Parse simplified LDAPDomainDump JSON exports."""

    tool_name = "ldapdomaindump"
    aliases = ("ldap-domain-dump",)
    supported_extensions = (".json",)

    def can_parse(self, content: str) -> float:
        """Score whether content is LDAPDomainDump data."""

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return 0.0
        if not isinstance(data, dict):
            return 0.0
        keys = {"users", "groups", "computers"} & set(data)
        score = len(keys) * 0.25
        if "ldapdomaindump" in json.dumps(data.get("meta", {})).casefold():
            score += 0.25
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse LDAPDomainDump JSON into domain objects."""

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return ParsedResult(self.tool_name, True, [], [], [], [], content)

        domain = str(data.get("domain") or "unknown")
        objects: list[DomainObject] = []
        for object_type in ("users", "groups", "computers"):
            for item in data.get(object_type, []):
                if isinstance(item, dict):
                    objects.append(_domain_object(item, object_type[:-1], domain))

        return ParsedResult(self.tool_name, False, [], [], [], objects, content)


def _domain_object(item: dict[str, Any], object_type: str, domain: str) -> DomainObject:
    name = str(item.get("name") or item.get("sAMAccountName") or "unknown")
    item_domain = str(item.get("domain") or domain)
    return DomainObject(
        name=name,
        object_type="computer" if object_type == "computer" else object_type,
        domain=item_domain,
        properties=dict(item),
        paths=[],
    )
