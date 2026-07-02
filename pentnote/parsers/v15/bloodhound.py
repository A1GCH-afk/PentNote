"""BloodHound JSON parser."""

from __future__ import annotations

import json
from typing import Any

from pentnote.models import DomainObject, NetworkPath, ParsedResult
from pentnote.parsers.base import AbstractParser


class BloodHoundParser(AbstractParser):
    """Parse simplified BloodHound JSON exports."""

    tool_name = "bloodhound"
    aliases = ("sharphound",)
    supported_extensions = (".json",)

    def can_parse(self, content: str) -> float:
        """Score whether content looks like BloodHound graph JSON."""

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return 0.0
        if not isinstance(data, dict):
            return 0.0
        score = 0.0
        if "nodes" in data and "edges" in data:
            score += 0.8
        if "bloodhound" in json.dumps(data.get("meta", {})).casefold():
            score += 0.2
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse BloodHound JSON into domain graph objects."""

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return ParsedResult(
                tool=self.tool_name,
                partial=True,
                hosts=[],
                credentials=[],
                findings=[],
                domain_objects=[],
                raw_text=content,
            )

        nodes = data.get("nodes", []) if isinstance(data, dict) else []
        edges = data.get("edges", []) if isinstance(data, dict) else []
        paths_by_source = _paths_by_source(edges)
        domain_objects = [
            _domain_object(node, paths_by_source)
            for node in nodes
            if isinstance(node, dict)
        ]
        return ParsedResult(
            tool=self.tool_name,
            partial=False,
            hosts=[],
            credentials=[],
            findings=[],
            domain_objects=domain_objects,
            raw_text=content,
        )


def _paths_by_source(edges: list[Any]) -> dict[str, list[NetworkPath]]:
    paths: dict[str, list[NetworkPath]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        relationship = str(edge.get("relationship") or edge.get("kind") or "Related")
        if not source or not target:
            continue
        paths.setdefault(source, []).append(NetworkPath(source, target, relationship))
    return paths


def _domain_object(
    node: dict[str, Any],
    paths_by_source: dict[str, list[NetworkPath]],
) -> DomainObject:
    name = str(node.get("name") or node.get("id") or "unknown")
    object_id = str(node.get("id") or name)
    properties = dict(node.get("properties") or {})
    domain = str(
        node.get("domain") or properties.get("domain") or _domain_from_name(name)
    )
    object_type = str(node.get("type") or node.get("label") or "unknown").casefold()
    return DomainObject(
        name=name,
        object_type=object_type,
        domain=domain,
        properties=properties,
        paths=paths_by_source.get(object_id, []) + paths_by_source.get(name, []),
    )


def _domain_from_name(name: str) -> str:
    if "@" in name:
        return name.split("@", 1)[1].casefold()
    return "unknown"
