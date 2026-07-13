"""Deterministic NetworkX layout helpers for Obsidian Canvas."""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import networkx as nx

    from pentnote.graph.bloodhound import DomainGraph

CoordinateMap = dict[str, tuple[int, int]]
EdgePair = tuple[str, str]

DEFAULT_SEED = 42
DEFAULT_SCALE = 720
DEFAULT_NODE_WIDTH = 360
DEFAULT_NODE_HEIGHT = 190
DEFAULT_PADDING = 180


class LayoutMode(StrEnum):
    """Canvas layout strategy."""

    AUTO = "auto"
    RADIAL = "radial"
    GRID = "grid"
    TREE = "tree"
    FORCE = "force"


def compute_layout(
    graph: DomainGraph,
    mode: LayoutMode = LayoutMode.AUTO,
) -> CoordinateMap:
    """Compute a deterministic layout for a domain graph."""

    selected = LayoutMode(mode)
    node_count = len(graph.nodes)
    if selected == LayoutMode.AUTO:
        if node_count <= 20:
            selected = LayoutMode.RADIAL
        elif node_count <= 60:
            selected = LayoutMode.TREE
        else:
            selected = LayoutMode.GRID

    if selected == LayoutMode.RADIAL:
        return _radial_layout(graph)
    if selected == LayoutMode.TREE:
        return _tree_layout(graph)
    if selected == LayoutMode.FORCE and _networkx_available():
        return _force_layout(graph)
    return _grid_layout(graph)


def _grid_layout(
    graph: DomainGraph,
    *,
    seed: int = DEFAULT_SEED,
    scale: int = DEFAULT_SCALE,
    node_width: int = DEFAULT_NODE_WIDTH,
    node_height: int = DEFAULT_NODE_HEIGHT,
    padding: int = DEFAULT_PADDING,
) -> CoordinateMap:
    """Return the existing deterministic grid-snapped force layout."""

    return layout_nodes(
        [node.id for node in graph.nodes],
        [(edge.source, edge.target) for edge in graph.edges],
        seed=seed,
        scale=scale,
        node_width=node_width,
        node_height=node_height,
        padding=padding,
    )


def _radial_layout(graph: DomainGraph) -> CoordinateMap:
    ring_radius = [0, 300, 600, 900, 1200]
    rings: dict[int, list[str]] = {index: [] for index in range(len(ring_radius))}
    for node in sorted(
        graph.nodes, key=lambda item: (item.object_type, item.name, item.id)
    ):
        ring = _node_ring(node)
        rings.setdefault(ring, []).append(node.id)

    positions: CoordinateMap = {}
    for ring, node_ids in sorted(rings.items()):
        if not node_ids:
            continue
        radius = ring_radius[min(ring, len(ring_radius) - 1)]
        if radius == 0:
            for index, node_id in enumerate(node_ids):
                positions[node_id] = (index * (DEFAULT_NODE_WIDTH + DEFAULT_PADDING), 0)
            continue
        for index, node_id in enumerate(node_ids):
            angle = 2 * math.pi * index / len(node_ids)
            positions[node_id] = (
                int(round(math.cos(angle) * radius)),
                int(round(math.sin(angle) * radius)),
            )
    return positions


def _tree_layout(graph: DomainGraph) -> CoordinateMap:
    type_order = {
        "domain": 0,
        "group": 1,
        "computer": 2,
        "user": 3,
        "share": 4,
    }
    rows: dict[int, list[str]] = {}
    for node in sorted(
        graph.nodes, key=lambda item: (item.object_type, item.name, item.id)
    ):
        row = type_order.get(node.object_type.casefold(), 5)
        rows.setdefault(row, []).append(node.id)

    positions: CoordinateMap = {}
    x_gap = DEFAULT_NODE_WIDTH + DEFAULT_PADDING
    y_gap = DEFAULT_NODE_HEIGHT + DEFAULT_PADDING
    for row, node_ids in sorted(rows.items()):
        start_x = -((len(node_ids) - 1) * x_gap) // 2
        for index, node_id in enumerate(node_ids):
            positions[node_id] = (start_x + (index * x_gap), row * y_gap)
    return positions


def _force_layout(graph: DomainGraph) -> CoordinateMap:
    positions = _networkx_positions(
        [node.id for node in graph.nodes],
        [(edge.source, edge.target) for edge in graph.edges],
        seed=DEFAULT_SEED,
        scale=DEFAULT_SCALE,
    )
    return _snap_to_grid(
        positions,
        node_width=DEFAULT_NODE_WIDTH,
        node_height=DEFAULT_NODE_HEIGHT,
        padding=DEFAULT_PADDING,
    )


def _node_ring(node: object) -> int:
    object_type = getattr(node, "object_type", "unknown").casefold()
    name = getattr(node, "name", "").casefold()
    properties = getattr(node, "properties", {}) or {}
    if object_type == "domain" or _truthy(properties.get("isdc")):
        return 0
    if "domain admins" in name or "krbtgt" in name or _truthy(properties.get("isDC")):
        return 1
    if object_type == "computer":
        return 2
    if object_type == "user":
        return 3
    if object_type in {"group", "share"}:
        return 4
    return 4


def _networkx_available() -> bool:
    """Return whether the optional force-directed layout backend is usable.

    ``networkx.spring_layout`` requires ``numpy`` at runtime. Newer NetworkX
    releases no longer install numpy automatically, so both must be importable
    before the force layout can run; otherwise callers fall back to the
    deterministic radial layout.
    """
    try:
        import networkx  # noqa: F401
        import numpy  # noqa: F401
    except ImportError:
        return False
    return True


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).casefold() in {"1", "true", "yes"}


def layout_nodes(
    node_ids: Sequence[str],
    edges: Iterable[EdgePair],
    *,
    seed: int = DEFAULT_SEED,
    scale: int = DEFAULT_SCALE,
    node_width: int = DEFAULT_NODE_WIDTH,
    node_height: int = DEFAULT_NODE_HEIGHT,
    padding: int = DEFAULT_PADDING,
) -> CoordinateMap:
    """Lay out node IDs and directed edges for Obsidian Canvas.

    NetworkX provides the force-directed geometry. A deterministic grid snap is
    applied after scaling so Canvas nodes keep enough space to render cleanly.
    """

    normalized_edges = _normalize_edges(edges)
    normalized_node_ids = _normalize_node_ids(node_ids, normalized_edges)
    if not normalized_node_ids:
        return {}
    if len(normalized_node_ids) == 1:
        return {normalized_node_ids[0]: (0, 0)}

    positions = _networkx_positions(
        normalized_node_ids,
        normalized_edges,
        seed=seed,
        scale=scale,
    )
    return _snap_to_grid(
        positions,
        node_width=node_width,
        node_height=node_height,
        padding=padding,
    )


def _networkx_positions(
    node_ids: Sequence[str],
    edges: Sequence[EdgePair],
    *,
    seed: int,
    scale: int,
) -> dict[str, tuple[float, float]]:
    node_set = set(node_ids)
    graph_edges = [
        (source, target)
        for source, target in edges
        if source in node_set and target in node_set
    ]

    if not _networkx_available():
        return _radial_positions(node_ids, scale=scale)

    if not graph_edges:
        return _radial_positions(node_ids, scale=scale)

    import networkx as nx

    nx_graph: nx.DiGraph = nx.DiGraph()
    nx_graph.add_nodes_from(node_ids)
    nx_graph.add_edges_from(graph_edges)

    return _component_positions(nx_graph, seed=seed, scale=scale)


def _component_positions(
    nx_graph: object,
    *,
    seed: int,
    scale: int,
) -> dict[str, tuple[float, float]]:
    import networkx as nx

    positions: dict[str, tuple[float, float]] = {}
    component_gap = scale * 2.4
    component_x = 0.0

    components = sorted(
        nx.connected_components(nx_graph.to_undirected()),
        key=lambda component: (-len(component), sorted(component)[0]),
    )
    for component_index, component_nodes in enumerate(components):
        subgraph = nx_graph.subgraph(sorted(component_nodes)).copy()
        component_width = max(scale, math.sqrt(len(subgraph)) * scale * 1.45)
        component_scale = max(1.0, math.sqrt(len(subgraph)) * 1.35)
        iterations = max(200, min(1000, len(subgraph) * 35))

        if len(subgraph) == 1:
            local_positions = {next(iter(subgraph.nodes)): (0.0, 0.0)}
        else:
            local_positions = nx.spring_layout(
                subgraph,
                seed=seed + component_index,
                scale=component_scale,
                iterations=iterations,
                k=1.4 / math.sqrt(len(subgraph)),
            )

        min_x = min(float(position[0]) * scale for position in local_positions.values())
        max_x = max(float(position[0]) * scale for position in local_positions.values())
        min_y = min(float(position[1]) * scale for position in local_positions.values())
        max_y = max(float(position[1]) * scale for position in local_positions.values())
        local_width = max_x - min_x
        local_height = max_y - min_y

        offset_x = component_x - min_x
        offset_y = -(min_y + (local_height / 2))
        for node_id, position in local_positions.items():
            positions[str(node_id)] = (
                float(position[0]) * scale + offset_x,
                float(position[1]) * scale + offset_y,
            )

        component_x += max(component_width, local_width) + component_gap

    return _center_positions(positions)


def _radial_positions(
    node_ids: Sequence[str],
    *,
    scale: int,
) -> dict[str, tuple[float, float]]:
    if len(node_ids) == 1:
        return {node_ids[0]: (0.0, 0.0)}

    result: dict[str, tuple[float, float]] = {}
    radius = max(float(scale), (len(node_ids) * scale) / (2 * math.pi))
    for index, node_id in enumerate(sorted(node_ids)):
        angle = 2 * math.pi * index / len(node_ids)
        result[node_id] = (
            math.cos(angle) * radius,
            math.sin(angle) * radius,
        )
    return result


def _center_positions(
    positions: dict[str, tuple[float, float]],
) -> dict[str, tuple[float, float]]:
    if not positions:
        return {}
    min_x = min(position[0] for position in positions.values())
    max_x = max(position[0] for position in positions.values())
    min_y = min(position[1] for position in positions.values())
    max_y = max(position[1] for position in positions.values())
    center_x = min_x + ((max_x - min_x) / 2)
    center_y = min_y + ((max_y - min_y) / 2)
    return {
        node_id: (x_pos - center_x, y_pos - center_y)
        for node_id, (x_pos, y_pos) in positions.items()
    }


def _snap_to_grid(
    positions: dict[str, tuple[float, float]],
    *,
    node_width: int,
    node_height: int,
    padding: int,
) -> CoordinateMap:
    cell_width = max(1, node_width + padding)
    cell_height = max(1, node_height + padding)
    occupied: set[tuple[int, int]] = set()
    snapped: CoordinateMap = {}

    for node_id, (x_pos, y_pos) in sorted(
        positions.items(),
        key=lambda item: (item[1][0], item[1][1], item[0]),
    ):
        desired_cell = (
            round(x_pos / cell_width),
            round(y_pos / cell_height),
        )
        cell = _nearest_open_cell(desired_cell, occupied)
        occupied.add(cell)
        snapped[node_id] = (cell[0] * cell_width, cell[1] * cell_height)

    return snapped


def _nearest_open_cell(
    desired_cell: tuple[int, int],
    occupied: set[tuple[int, int]],
) -> tuple[int, int]:
    if desired_cell not in occupied:
        return desired_cell

    desired_column, desired_row = desired_cell
    search_radius = 1
    while True:
        candidates: list[tuple[int, int]] = []
        for column_delta in range(-search_radius, search_radius + 1):
            for row_delta in range(-search_radius, search_radius + 1):
                if max(abs(column_delta), abs(row_delta)) != search_radius:
                    continue
                candidate = (
                    desired_column + column_delta,
                    desired_row + row_delta,
                )
                if candidate not in occupied:
                    candidates.append(candidate)
        if candidates:
            return min(
                candidates,
                key=lambda cell: (
                    (cell[0] - desired_column) ** 2 + (cell[1] - desired_row) ** 2,
                    cell[1],
                    cell[0],
                ),
            )
        search_radius += 1


def _normalize_node_ids(
    node_ids: Sequence[str],
    edges: Sequence[EdgePair],
) -> list[str]:
    values = {str(node_id) for node_id in node_ids if str(node_id)}
    for source, target in edges:
        values.add(source)
        values.add(target)
    return sorted(values)


def _normalize_edges(edges: Iterable[EdgePair]) -> list[EdgePair]:
    normalized: set[EdgePair] = set()
    for source, target in edges:
        source_id = str(source)
        target_id = str(target)
        if source_id and target_id:
            normalized.add((source_id, target_id))
    return sorted(normalized)
