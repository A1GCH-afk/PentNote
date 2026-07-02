"""BloodHound/domain graph normalization for Obsidian Canvas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field

from pentnote.core.models import PentNoteModel
from pentnote.workspace.store import slugify


class GraphNode(PentNoteModel):
    """Normalized BloodHound node."""

    id: str
    name: str
    object_type: str
    note_path: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(PentNoteModel):
    """Normalized relationship edge."""

    source: str
    target: str
    relationship: str
    path_type: str = "normal"


class DomainGraph(PentNoteModel):
    """Normalized graph ready for layout and Canvas rendering."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]


def load_bloodhound_graph(path: Path, *, vault_root: Path | None = None) -> DomainGraph:
    """Load a BloodHound JSON export or SharpHound collection folder."""

    if path.is_dir():
        return normalize_sharphound_collection(path, vault_root=vault_root)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return DomainGraph([], [])
    if "data" in data and "meta" in data:
        return normalize_sharphound_documents([data], vault_root=vault_root)
    return normalize_bloodhound(data, vault_root=vault_root)


def normalize_sharphound_collection(
    directory: Path,
    *,
    vault_root: Path | None = None,
) -> DomainGraph:
    """Normalize a folder of SharpHound ``*_users.json`` style files."""

    documents: list[dict[str, Any]] = []
    bloodhound_documents: list[dict[str, Any]] = []
    for path in sorted(directory.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            documents.append(data)
        elif isinstance(data, dict) and (
            isinstance(data.get("nodes"), list) or isinstance(data.get("edges"), list)
        ):
            bloodhound_documents.append(data)

    graphs = [
        normalize_bloodhound(document, vault_root=vault_root)
        for document in bloodhound_documents
    ]
    if documents:
        graphs.append(normalize_sharphound_documents(documents, vault_root=vault_root))
    return _merge_graphs(graphs)


def normalize_sharphound_documents(
    documents: list[dict[str, Any]],
    *,
    vault_root: Path | None = None,
) -> DomainGraph:
    """Normalize SharpHound v5 collection documents into graph records."""

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    referenced_nodes: dict[str, GraphNode] = {}
    for document in documents:
        object_type = _singular_type(
            str(document.get("meta", {}).get("type") or "unknown")
        )
        for item in document.get("data", []):
            if not isinstance(item, dict):
                continue
            node = _sharphound_node(item, object_type, vault_root)
            if node is None:
                continue
            nodes.append(node)
            edges.extend(_sharphound_edges(item, node.id))
            for referenced_node in _sharphound_referenced_nodes(item, vault_root):
                referenced_nodes.setdefault(referenced_node.id, referenced_node)

    known_ids = {node.id for node in nodes}
    for node_id, referenced_node in sorted(referenced_nodes.items()):
        if node_id not in known_ids:
            nodes.append(referenced_node)
            known_ids.add(node_id)

    for missing in sorted(
        ({edge.source for edge in edges} | {edge.target for edge in edges}) - known_ids
    ):
        nodes.append(
            GraphNode(
                id=missing,
                name=missing,
                object_type="unknown",
                note_path=_domain_note_path("unknown", missing, vault_root),
            )
        )
    return DomainGraph(nodes=_dedupe_nodes(nodes), edges=_dedupe_edges(edges))


def normalize_bloodhound(
    data: dict[str, Any],
    *,
    vault_root: Path | None = None,
) -> DomainGraph:
    """Normalize BloodHound-like ``nodes`` and ``edges`` into stable records."""

    raw_nodes = data.get("nodes", [])
    raw_edges = data.get("edges", [])
    if not isinstance(raw_nodes, list):
        raw_nodes = []
    if not isinstance(raw_edges, list):
        raw_edges = []

    nodes: list[GraphNode] = []
    known_ids: set[str] = set()
    for item in raw_nodes:
        if not isinstance(item, dict):
            continue
        node_id = str(item.get("id") or item.get("objectid") or item.get("name") or "")
        if not node_id:
            continue
        name = str(item.get("name") or node_id)
        object_type = str(item.get("type") or item.get("label") or "unknown").casefold()
        properties = (
            item.get("properties") if isinstance(item.get("properties"), dict) else {}
        )
        nodes.append(
            GraphNode(
                id=node_id,
                name=name,
                object_type=object_type,
                note_path=_domain_note_path(object_type, name, vault_root),
                properties=properties,
            )
        )
        known_ids.add(node_id)
        known_ids.add(name)

    shortest_pairs = _path_edge_pairs(data)
    edges: list[GraphEdge] = []
    for item in raw_edges:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or item.get("start") or item.get("from") or "")
        target = str(item.get("target") or item.get("end") or item.get("to") or "")
        if not source or not target:
            continue
        relationship = str(
            item.get("relationship")
            or item.get("kind")
            or item.get("label")
            or "Related"
        )
        path_type = str(
            item.get("path_type")
            or item.get("pathType")
            or _edge_path_type(source, target, relationship, shortest_pairs)
        )
        edges.append(
            GraphEdge(
                source=source,
                target=target,
                relationship=relationship,
                path_type=path_type,
            )
        )

    edge_endpoint_ids = {edge.source for edge in edges} | {
        edge.target for edge in edges
    }
    for missing in sorted(edge_endpoint_ids - known_ids):
        nodes.append(
            GraphNode(
                id=missing,
                name=missing,
                object_type="unknown",
                note_path=_domain_note_path("unknown", missing, vault_root),
                properties={},
            )
        )

    return DomainGraph(nodes=_dedupe_nodes(nodes), edges=_dedupe_edges(edges))


def _domain_note_path(object_type: str, name: str, vault_root: Path | None) -> str:
    folder = {
        "user": "users",
        "group": "groups",
        "computer": "computers",
        "share": "shares",
        "template": "templates",
        "gpo": "gpos",
        "acl": "acls",
    }.get(object_type, "other")
    relative = Path("notes") / "domain" / folder / f"{slugify(name)}.md"
    if vault_root is None:
        return relative.as_posix()
    path = vault_root / relative
    if path.exists():
        return relative.as_posix()
    return relative.as_posix()


def _singular_type(value: str) -> str:
    mapping = {
        "users": "user",
        "computers": "computer",
        "groups": "group",
        "domains": "domain",
        "gpos": "gpo",
        "ous": "ou",
        "containers": "container",
    }
    return mapping.get(value.casefold(), value.casefold().rstrip("s") or "unknown")


def _sharphound_node(
    item: dict[str, Any],
    object_type: str,
    vault_root: Path | None,
) -> GraphNode | None:
    object_id = str(item.get("ObjectIdentifier") or item.get("ObjectID") or "")
    properties = (
        item.get("Properties") if isinstance(item.get("Properties"), dict) else {}
    )
    name = str(properties.get("name") or properties.get("samaccountname") or object_id)
    if not object_id:
        return None
    return GraphNode(
        id=object_id,
        name=name,
        object_type=object_type,
        note_path=_domain_note_path(object_type, name, vault_root),
        properties=dict(properties),
    )


def _sharphound_edges(item: dict[str, Any], object_id: str) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for member in _list_dicts(item.get("Members")):
        target = _object_identifier(member)
        if target:
            edges.append(
                GraphEdge(
                    source=target,
                    target=object_id,
                    relationship="MemberOf",
                    path_type=_relationship_path_type("MemberOf", target, object_id),
                )
            )

    for ace in _list_dicts(item.get("Aces")):
        source = str(ace.get("PrincipalSID") or "")
        relationship = str(ace.get("RightName") or "ACL")
        if source:
            edges.append(
                GraphEdge(
                    source=source,
                    target=object_id,
                    relationship=relationship,
                    path_type=_relationship_path_type(relationship, source, object_id),
                )
            )

    for child in _list_dicts(item.get("ChildObjects")):
        target = _object_identifier(child)
        if target:
            edges.append(
                GraphEdge(source=object_id, target=target, relationship="Contains")
            )

    for target in _list_dicts(item.get("AllowedToDelegate")):
        target_id = _object_identifier(target)
        if target_id:
            edges.append(
                GraphEdge(
                    source=object_id,
                    target=target_id,
                    relationship="AllowedToDelegate",
                    path_type=_relationship_path_type(
                        "AllowedToDelegate", object_id, target_id
                    ),
                )
            )

    for target in _list_dicts(item.get("AllowedToAct")):
        target_id = _object_identifier(target)
        if target_id:
            edges.append(
                GraphEdge(
                    source=target_id,
                    target=object_id,
                    relationship="AllowedToAct",
                    path_type=_relationship_path_type(
                        "AllowedToAct", target_id, object_id
                    ),
                )
            )

    collected_relationships = {
        "LocalAdmins": "AdminTo",
        "PSRemoteUsers": "CanPSRemote",
        "RemoteDesktopUsers": "CanRDP",
        "DcomUsers": "ExecuteDCOM",
        "Sessions": "HasSession",
        "PrivilegedSessions": "HasPrivilegedSession",
        "RegistrySessions": "HasRegistrySession",
    }
    for key, relationship in collected_relationships.items():
        value = item.get(key)
        if not isinstance(value, dict):
            continue
        for result in _list_dicts(value.get("Results")):
            source = _object_identifier(result)
            if source:
                edges.append(
                    GraphEdge(
                        source=source,
                        target=object_id,
                        relationship=relationship,
                        path_type=_relationship_path_type(
                            relationship, source, object_id
                        ),
                    )
                )
    return edges


def _sharphound_referenced_nodes(
    item: dict[str, Any],
    vault_root: Path | None,
) -> list[GraphNode]:
    referenced: list[GraphNode] = []
    for key in (
        "Members",
        "ChildObjects",
        "AllowedToDelegate",
        "AllowedToAct",
    ):
        referenced.extend(
            node
            for value in _list_dicts(item.get(key))
            if (node := _referenced_node(value, vault_root)) is not None
        )

    referenced.extend(
        node
        for ace in _list_dicts(item.get("Aces"))
        if (node := _principal_node(ace, vault_root)) is not None
    )

    for key in (
        "LocalAdmins",
        "PSRemoteUsers",
        "RemoteDesktopUsers",
        "DcomUsers",
        "Sessions",
        "PrivilegedSessions",
        "RegistrySessions",
    ):
        value = item.get(key)
        if not isinstance(value, dict):
            continue
        referenced.extend(
            node
            for result in _list_dicts(value.get("Results"))
            if (node := _referenced_node(result, vault_root)) is not None
        )
    return referenced


def _referenced_node(
    value: dict[str, Any],
    vault_root: Path | None,
) -> GraphNode | None:
    object_id = _object_identifier(value)
    if not object_id:
        return None
    object_type = _singular_type(
        str(
            value.get("ObjectType")
            or value.get("ObjectTypeName")
            or value.get("Type")
            or value.get("type")
            or "unknown"
        )
    )
    name = _object_name(value, object_id)
    return GraphNode(
        id=object_id,
        name=name,
        object_type=object_type,
        note_path=_domain_note_path(object_type, name, vault_root),
        properties=dict(value.get("Properties") or {}),
    )


def _principal_node(
    value: dict[str, Any],
    vault_root: Path | None,
) -> GraphNode | None:
    object_id = _object_identifier(value)
    if not object_id:
        return None
    object_type = _singular_type(
        str(value.get("PrincipalType") or value.get("ObjectType") or "unknown")
    )
    name = _object_name(value, object_id)
    return GraphNode(
        id=object_id,
        name=name,
        object_type=object_type,
        note_path=_domain_note_path(object_type, name, vault_root),
        properties=dict(value.get("Properties") or {}),
    )


def _object_name(value: dict[str, Any], fallback: str) -> str:
    properties = (
        value.get("Properties") if isinstance(value.get("Properties"), dict) else {}
    )
    for key in (
        "ObjectName",
        "PrincipalName",
        "DisplayName",
        "Name",
        "name",
        "samaccountname",
    ):
        if name := value.get(key):
            return str(name)
        if name := properties.get(key):
            return str(name)
    return fallback


def _list_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _object_identifier(value: dict[str, Any]) -> str:
    return str(
        value.get("ObjectIdentifier")
        or value.get("ObjectId")
        or value.get("ObjectID")
        or value.get("PrincipalSID")
        or value.get("SID")
        or ""
    )


def _path_edge_pairs(data: dict[str, Any]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for key in ("ShortestPaths", "shortestPaths", "Paths", "paths"):
        _collect_path_pairs(data.get(key), pairs)
    return pairs


def _collect_path_pairs(value: Any, pairs: set[tuple[str, str]]) -> None:
    if isinstance(value, dict):
        source = str(
            value.get("source") or value.get("start") or value.get("from") or ""
        )
        target = str(value.get("target") or value.get("end") or value.get("to") or "")
        if source and target:
            pairs.add((source, target))
        for nested_key in ("edges", "Edges", "path", "Path", "links", "Links"):
            _collect_path_pairs(value.get(nested_key), pairs)
    elif isinstance(value, list):
        for item in value:
            _collect_path_pairs(item, pairs)


def _edge_path_type(
    source: str,
    target: str,
    relationship: str,
    shortest_pairs: set[tuple[str, str]],
) -> str:
    if (source, target) in shortest_pairs:
        return "shortest_path"
    return _relationship_path_type(relationship, source, target)


def _relationship_path_type(relationship: str, source: str, target: str) -> str:
    normalized = relationship.casefold().strip()
    if normalized == "memberof" and "domain admins" in target.casefold():
        return "attack_path"
    if normalized in {
        "adminto",
        "hassession",
        "dcsync",
        "genericall",
        "writedacl",
    }:
        return "attack_path"
    return "normal"


def _path_rank(path_type: str) -> int:
    return {"normal": 0, "attack_path": 1, "shortest_path": 2}.get(path_type, 0)


def _dedupe_nodes(nodes: list[GraphNode]) -> list[GraphNode]:
    seen: set[str] = set()
    deduped: list[GraphNode] = []
    for node in nodes:
        if node.id in seen:
            continue
        seen.add(node.id)
        deduped.append(node)
    return sorted(
        deduped, key=lambda item: (item.object_type, item.name.casefold(), item.id)
    )


def _dedupe_edges(edges: list[GraphEdge]) -> list[GraphEdge]:
    deduped_by_key: dict[tuple[str, str, str], GraphEdge] = {}
    for edge in edges:
        key = (edge.source, edge.target, edge.relationship)
        existing = deduped_by_key.get(key)
        if existing is not None and _path_rank(existing.path_type) >= _path_rank(
            edge.path_type
        ):
            continue
        deduped_by_key[key] = edge
    return sorted(
        deduped_by_key.values(),
        key=lambda item: (item.source, item.target, item.relationship, item.path_type),
    )


def _merge_graphs(graphs: list[DomainGraph]) -> DomainGraph:
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    for graph in graphs:
        nodes.extend(graph.nodes)
        edges.extend(graph.edges)
    return DomainGraph(nodes=_dedupe_nodes(nodes), edges=_dedupe_edges(edges))
