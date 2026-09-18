import { useId, useMemo } from 'react';
import type { LineageEdge, LineageNode } from '../services/api';

export function downstream(nodes: LineageNode[], edges: LineageEdge[], source: string): Set<string> {
  const known = new Set(nodes.map((node) => node.id));
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    if (known.has(edge.source) && known.has(edge.target)) adjacency.set(edge.source, [...(adjacency.get(edge.source) ?? []), edge.target]);
  }
  const reached = new Set<string>();
  if (!known.has(source)) return reached;
  const queue = [source];
  reached.add(source);
  for (let index = 0; index < queue.length; index++) {
    for (const target of adjacency.get(queue[index]) ?? []) {
      if (!reached.has(target)) { reached.add(target); queue.push(target); }
    }
  }
  return reached;
}
export const operationalNode = (node: LineageNode): boolean => ['dataset', 'model', 'inference', 'inference_record'].includes(node.type);

export default function LineageGraph({ nodes, edges, selected, onSelect }: { nodes: LineageNode[]; edges: LineageEdge[]; selected: string; onSelect: (id: string) => void }) {
  const arrow = useId().replace(/:/g, '');
  const reached = useMemo(() => downstream(nodes, edges, selected), [nodes, edges, selected]);
  const types = ['contributor', 'dataset', 'model', 'inference', 'finding'];
  const column = (type: string) => type === 'inference_record' ? 3 : types.indexOf(type);
  const known = nodes.filter((node) => column(node.type) >= 0);
  const unknown = nodes.filter((node) => column(node.type) < 0);
  const groups = types.map((_, index) => known.filter((node) => column(node.type) === index));
  const height = Math.max(280, 90 + Math.max(...groups.map((group) => group.length)) * 88);
  const positions = new Map(groups.flatMap((group, col) => group.map((node, row) => [node.id, { x: 18 + col * 226, y: 65 + row * 88 }] as const)));
  return <>
    <div className="graph-scroll"><svg className="lineage-svg" viewBox={`0 0 1130 ${height}`} style={{ minHeight: height }} role="group" aria-label="Directed lineage graph. Select a node to highlight its downstream blast radius.">
      <defs><marker id={arrow} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="context-stroke" /></marker></defs>
      {types.map((type, index) => <g key={type}><text x={18 + index * 226} y="28" className="graph-column-label">{type[0].toUpperCase() + type.slice(1)}</text><line x1={18 + index * 226} x2={210 + index * 226} y1="42" y2="42" className="chart-guide" /></g>)}
      {edges.map((edge, index) => {
        const start = positions.get(edge.source), end = positions.get(edge.target);
        if (!start || !end) return null;
        const active = reached.has(edge.source) && reached.has(edge.target);
        return <path key={`${edge.source}-${edge.target}-${index}`} d={`M ${start.x + 190} ${start.y + 29} C ${start.x + 222} ${start.y + 29}, ${end.x - 32} ${end.y + 29}, ${end.x} ${end.y + 29}`} className={`graph-edge ${active ? 'graph-edge-active' : ''}`} markerEnd={`url(#${arrow})`} />;
      })}
      {known.map((node) => {
        const position = positions.get(node.id);
        if (!position) return null;
        return <g key={node.id} transform={`translate(${position.x},${position.y})`} role="button" tabIndex={0} aria-pressed={selected === node.id} aria-label={`${node.type}: ${node.id}${node.orphan ? ', orphan: missing provenance' : ''}. Show downstream blast radius.`} onClick={() => onSelect(node.id)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(node.id); } }} className={`graph-node ${reached.has(node.id) ? 'graph-node-active' : ''} ${selected === node.id ? 'graph-node-selected' : ''} ${node.orphan ? 'graph-node-orphan' : ''}`}>
          <title>{node.id}{node.hash ? `\nHash: ${node.hash}` : '\nHash unavailable'}</title><rect width="190" height="58" rx="6" /><text x="12" y="24">{node.id.length > 23 ? `${node.id.slice(0, 21)}…` : node.id}</text><text x="12" y="43" className="graph-node-meta">{node.orphan ? 'Orphan · provenance gap' : node.hash ? 'Hash present · not verified' : 'Hash unavailable'}</text>
        </g>;
      })}
    </svg></div>
    {!!unknown.length && <div className="unknown-nodes"><p className="warning-text">{unknown.length} nodes have unsupported types and are listed outside the layered graph.</p>{unknown.map((node) => <button className="button small" key={node.id} onClick={() => onSelect(node.id)}>{node.id} ({node.type})</button>)}</div>}
    <div className="legend"><span><i className="key key-accent" />Selected downstream subgraph</span><span>Dashed node: missing provenance</span><span>Arrows: upstream → downstream</span></div>
  </>;
}
