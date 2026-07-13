"""Obsidian Canvas JSON writer for PentNote domain graphs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import click

from pentnote.core.models import CanvasWriteResult
from pentnote.graph.bloodhound import (
    DomainGraph,
    GraphEdge,
    GraphNode,
    load_bloodhound_graph,
)
from pentnote.graph.layout import LayoutMode, _truthy, compute_layout
from pentnote.workspace.store import slugify

NODE_WIDTH = 360
NODE_HEIGHT = 190

CanvasValue = str | int
CanvasObject = dict[str, CanvasValue]
CanvasDocument = dict[str, list[CanvasObject]]

NODE_COLORS = {
    "domain_admin": "#FF4444",
    "domain_controller": "#FF8800",
    "kerberoastable": "#FFAA00",
    "computer": "#4488FF",
    "user": "#44AA44",
    "group": "#888888",
    "share": "#AA44AA",
    "domain": "#FF8800",
    "unknown": "#888888",
}
EDGE_STYLES = {
    "normal": {"color": "#888888", "width": 1},
    "attack_path": {"color": "#FF8800", "width": 2},
    "shortest_path": {"color": "#FF4444", "width": 3},
}

HIGH_IMPACT_RELATIONSHIPS = {
    "addmember",
    "allowedtoact",
    "allowedtodelegate",
    "allextendedrights",
    "forcechangepassword",
    "genericall",
    "genericwrite",
    "owns",
    "writedacl",
    "writeowner",
}
REMOTE_ACCESS_RELATIONSHIPS = {
    "adminto",
    "canpsremote",
    "canrdp",
    "executedcom",
}
SESSION_RELATIONSHIPS = {
    "hassession",
    "hasprivilegedsession",
    "hasregistrysession",
}


def build_canvas(
    graph: DomainGraph,
    *,
    vault_root: Path | None = None,
    layout: LayoutMode = LayoutMode.AUTO,
    highlight_paths: bool = False,
) -> CanvasDocument:
    """Build Obsidian Canvas JSON from a normalized graph."""

    positions = compute_layout(graph, mode=layout)
    nodes: list[CanvasObject] = []
    node_ids: dict[str, str] = {}
    seen_nodes: set[str] = set()

    for node in graph.nodes:
        if node.id in seen_nodes:
            continue
        seen_nodes.add(node.id)

        canvas_id = _canvas_id("node", node.id)
        node_ids[node.id] = canvas_id
        x, y = positions.get(node.id, (0, 0))
        canvas_node: CanvasObject = {
            "id": canvas_id,
            "type": "file",
            "file": note_file_for_node(node, vault_root=vault_root),
            "x": x,
            "y": y,
            "width": NODE_WIDTH,
            "height": NODE_HEIGHT,
            "color": _node_color(node),
        }
        nodes.append(canvas_node)

    edges: list[CanvasObject] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for edge in graph.edges:
        from_node = node_ids.get(edge.source)
        to_node = node_ids.get(edge.target)
        if not from_node or not to_node:
            continue
        edge_key = (edge.source, edge.target, edge.relationship)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)

        from_side, to_side = _edge_sides(edge, positions)
        canvas_edge: CanvasObject = {
            "id": _canvas_id(
                "edge",
                f"{edge.source}\0{edge.relationship}\0{edge.target}",
            ),
            "fromNode": from_node,
            "fromSide": from_side,
            "toNode": to_node,
            "toSide": to_side,
            "toEnd": "arrow",
            "label": edge.relationship,
        }
        if highlight_paths:
            style = EDGE_STYLES.get(edge.path_type, EDGE_STYLES["normal"])
            canvas_edge["color"] = style["color"]
            canvas_edge["width"] = style["width"]
        else:
            edge_color = _edge_color(edge.relationship)
            if edge_color:
                canvas_edge["color"] = edge_color
        edges.append(
            canvas_edge,
        )
    if highlight_paths:
        nodes.insert(0, _legend_node(graph))
    return {"nodes": nodes, "edges": edges}


def write_canvas(
    graph: DomainGraph,
    output_path: Path,
    *,
    vault_root: Path | None = None,
    layout: LayoutMode = LayoutMode.AUTO,
    highlight_paths: bool = False,
) -> CanvasWriteResult:
    """Write a normalized graph to an Obsidian ``.canvas`` file."""

    resolved_vault_root = vault_root or output_path.parent
    _warn_large_graph(graph, layout)
    missing = _missing_note_nodes(graph, resolved_vault_root)
    if missing:
        click.echo(
            f"[!] {len(missing)} Canvas node(s) link to notes "
            "that do not exist yet:",
            err=True,
        )
        for node in missing[:5]:
            click.echo(
                f"    {_node_label(node)} -> "
                f"{note_file_for_node(node, vault_root=resolved_vault_root)}",
                err=True,
            )
        if len(missing) > 5:
            click.echo(f"    ... and {len(missing) - 5} more", err=True)
        click.echo(
            "[!] Run the relevant parsers first, then regenerate the Canvas.",
            err=True,
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(
            build_canvas(
                graph,
                vault_root=resolved_vault_root,
                layout=layout,
                highlight_paths=highlight_paths,
            ),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    tmp_path.replace(output_path)
    return CanvasWriteResult(written=output_path, missing_notes=missing)


def write_bloodhound_canvas(
    bloodhound_path: Path,
    output_path: Path,
    *,
    vault_root: Path | None = None,
    layout: LayoutMode = LayoutMode.AUTO,
    highlight_paths: bool = False,
) -> CanvasWriteResult:
    """Normalize a BloodHound export and write it as an Obsidian Canvas."""

    return write_canvas(
        load_bloodhound_graph(bloodhound_path, vault_root=vault_root),
        output_path,
        vault_root=vault_root,
        layout=layout,
        highlight_paths=highlight_paths,
    )


def _warn_large_graph(graph: DomainGraph, layout: LayoutMode) -> None:
    node_count = len(graph.nodes)
    if node_count <= 100:
        return
    selected = LayoutMode(layout)
    if selected in {LayoutMode.AUTO, LayoutMode.GRID}:
        click.echo(
            f"[!] Large graph ({node_count} nodes). Using grid layout. "
            "Consider --layout tree for better readability.",
            err=True,
        )


def attack_path_summary(graph: DomainGraph) -> dict[str, object]:
    """Summarize attack-path edges for CLI and Canvas annotations."""

    shortest = [edge for edge in graph.edges if edge.path_type == "shortest_path"]
    attack_edges = [
        edge
        for edge in graph.edges
        if edge.path_type in {"attack_path", "shortest_path"}
    ]
    relationships = sorted({edge.relationship for edge in attack_edges})
    return {
        "shortest_paths": len(shortest),
        "attack_paths": len(attack_edges),
        "critical_edges": relationships,
    }


def _legend_node(graph: DomainGraph) -> CanvasObject:
    summary = attack_path_summary(graph)
    critical_edges = ", ".join(summary["critical_edges"]) or "none"
    text = "\n".join(
        [
            "Attack Path Legend",
            "Red: Shortest Path to DA",
            "Orange: High-value attack edge",
            "Gray: Normal relationship",
            f"Found {summary['shortest_paths']} shortest paths to Domain Admins",
            f"Critical edges: {critical_edges}",
        ]
    )
    return {
        "id": "pentnote-attack-path-legend",
        "type": "text",
        "text": text,
        "x": -520,
        "y": -360,
        "width": 420,
        "height": 220,
        "color": "#FF4444",
    }


def _check_note_exists(note_path: Path, vault_root: Path) -> bool:
    full_path = vault_root / note_path
    return full_path.exists()


def _missing_note_nodes(graph: DomainGraph, vault_root: Path) -> list[GraphNode]:
    missing: list[GraphNode] = []
    for node in graph.nodes:
        note_path = Path(note_file_for_node(node, vault_root=vault_root))
        if not _check_note_exists(note_path, vault_root):
            missing.append(node)
    return missing


def _node_label(node: GraphNode) -> str:
    return node.name or node.id


def note_file_for_node(
    node: GraphNode,
    *,
    vault_root: Path | None = None,
) -> str:
    """Return the PentNote Markdown file path for a Canvas file node."""

    object_type = _normalized_node_type(node.object_type)
    name = node.name or node.id
    candidates = _note_candidates(node, object_type, name)
    existing = _first_existing(candidates, vault_root)
    if existing is not None:
        return existing
    return candidates[0]


def _note_candidates(
    node: GraphNode,
    object_type: str,
    name: str,
) -> list[str]:
    candidates: list[str] = []
    if node.note_path and node.note_path != "legacy":
        candidates.append(node.note_path)
    if object_type == "computer":
        candidates.append(_note_path("hosts", _computer_hostname(name)))
        candidates.append(_note_path("domain/computers", name))
        candidates.append(_note_path("domain", f"computer-{name}"))
    elif object_type == "user":
        candidates.append(_note_path("credentials/plaintext", _username(name)))
        candidates.append(_note_path("credentials/ntlm", _username(name)))
        candidates.append(_note_path("credentials", _username(name)))
        if domain := _principal_domain(name):
            candidates.append(
                _note_path("credentials/plaintext", f"{domain}-{_username(name)}")
            )
            candidates.append(
                _note_path("credentials/ntlm", f"{domain}-{_username(name)}")
            )
            candidates.append(_note_path("credentials", f"{domain}-{_username(name)}"))
        candidates.append(_note_path("domain/users", name))
        candidates.append(_note_path("domain", f"user-{name}"))
    elif object_type == "group":
        candidates.append(_note_path("domain/groups", name))
        candidates.append(_note_path("domain", name))
        candidates.append(_note_path("domain", f"{object_type}-{name}"))
    elif object_type == "domain":
        candidates.append(_note_path("domain", name))
        candidates.append(_note_path("domain", f"{object_type}-{name}"))
    else:
        candidates.append(node.note_path or _note_path("domain", name))
        candidates.append(_note_path("domain", name))

    if node.note_path:
        candidates.append(node.note_path)
    return _dedupe_paths(candidates)


def _canvas_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    stem = slugify(value)[:40]
    return f"{prefix}-{stem}-{digest}"


def _note_path(folder: str, value: str) -> str:
    return (Path("notes") / folder / f"{slugify(value)}.md").as_posix()


def _first_existing(
    candidates: list[str],
    vault_root: Path | None,
) -> str | None:
    if vault_root is None:
        return None
    for candidate in candidates:
        if (vault_root / candidate).exists():
            return candidate
    return None


def _dedupe_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        deduped.append(path)
    return deduped


def _normalized_node_type(value: str) -> str:
    normalized = value.casefold().strip()
    aliases = {
        "computers": "computer",
        "domains": "domain",
        "groups": "group",
        "users": "user",
    }
    return aliases.get(normalized, normalized or "unknown")


def _computer_hostname(name: str) -> str:
    hostname = _strip_domain_prefix(name).strip()
    return hostname.removesuffix("$") or name


def _username(name: str) -> str:
    username = _strip_domain_prefix(name).strip()
    if "@" in username:
        username = username.split("@", 1)[0]
    return username.removesuffix("$") or name


def _principal_domain(name: str) -> str | None:
    if "\\" in name:
        domain, _username_value = name.split("\\", 1)
        return domain or None
    if "@" in name:
        _username_value, domain = name.split("@", 1)
        return domain or None
    return None


def _strip_domain_prefix(value: str) -> str:
    if "\\" not in value:
        return value
    return value.rsplit("\\", 1)[-1]


def _node_color(node: GraphNode) -> str:
    return NODE_COLORS.get(_node_role(node), NODE_COLORS["unknown"])


def _node_role(node: GraphNode) -> str:
    properties = node.properties or {}
    if _is_domain_admin(node):
        return "domain_admin"
    if _truthy(properties.get("isDC")) or _truthy(properties.get("isdc")):
        return "domain_controller"
    if _truthy(properties.get("hasSPN")) or _truthy(properties.get("hasspn")):
        return "kerberoastable"
    object_type = _normalized_node_type(node.object_type)
    return object_type if object_type in NODE_COLORS else "unknown"


def _is_domain_admin(node: GraphNode) -> bool:
    principal = _username(node.name).replace("-", " ").casefold()
    return "domain admins" in principal


def _edge_sides(
    edge: GraphEdge,
    positions: dict[str, tuple[int, int]],
) -> tuple[str, str]:
    source_position = positions.get(edge.source)
    target_position = positions.get(edge.target)
    if source_position is None or target_position is None:
        return "right", "left"

    source_x, source_y = source_position
    target_x, target_y = target_position
    delta_x = target_x - source_x
    delta_y = target_y - source_y
    if abs(delta_x) >= abs(delta_y):
        if delta_x >= 0:
            return "right", "left"
        return "left", "right"
    if delta_y >= 0:
        return "bottom", "top"
    return "top", "bottom"


def _edge_color(relationship: str) -> str | None:
    normalized = relationship.casefold().strip()
    if normalized in HIGH_IMPACT_RELATIONSHIPS:
        return "1"
    if normalized in REMOTE_ACCESS_RELATIONSHIPS:
        return "2"
    if normalized == "memberof":
        return "6"
    if normalized in SESSION_RELATIONSHIPS:
        return "5"
    return None
