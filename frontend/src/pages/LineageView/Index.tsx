import { useCallback, useMemo, useState } from 'react';
import { getAssessments, getLineage, percent, display, type Asset, type ProvenanceRecord } from '../../services/api';
import { useApi, type ApiState } from '../../hooks/useApi';
import Panel from '../../components/Panel';
import StatusBanner from '../../components/StatusBanner';
import LineageGraph, { downstream, operationalNode } from '../../components/LineageGraph';

const failed = (state: string): boolean => /fail|invalid|tamper|mismatch|duplicate|replayed|rejected/i.test(state);
const verified = (state: string): boolean => /^(verified|valid|passed|ok|unique)$/i.test(state);
function State({ value }: { value: string }) {
  return <span className={`badge badge-${failed(value) ? 'error' : verified(value) ? 'success' : 'warning'}`}>{value}</span>;
}

export default function LineageView({ assets, assetId, onAssetChange }: { assets: ApiState<Asset[]>; assetId: string; onAssetChange: (id: string) => void }) {
  const fetchLineage = useCallback((signal: AbortSignal) => getLineage(assetId, signal), [assetId]);
  const lineage = useApi(fetchLineage, { enabled: !!assetId });
  const assessments = useApi(getAssessments, { pollInterval: 60000 });
  const [selection, setSelection] = useState({ assetId: '', nodeId: '' });
  const nodes = lineage.data?.nodes ?? [];
  const selected = selection.assetId === assetId && nodes.some((node) => node.id === selection.nodeId) ? selection.nodeId : assetId;
  const radius = useMemo(() => downstream(lineage.data?.nodes ?? [], lineage.data?.edges ?? [], selected), [lineage.data, selected]);
  const affected = nodes.filter((node) => node.id !== selected && radius.has(node.id) && operationalNode(node));
  const total = nodes.filter((node) => node.id !== selected && operationalNode(node)).length;
  const selectedNode = nodes.find((node) => node.id === selected);
  const records: ProvenanceRecord[] = lineage.data?.provenance_records.length ? lineage.data.provenance_records : nodes.filter((node) => ['inference', 'inference_record'].includes(node.type)).map((node) => ({ id: node.id, record_hash: node.hash, previous_record_hash: '', signature: '', hash_state: 'unavailable', signature_state: 'unavailable', replay_state: 'unavailable', sequence_number: '—' }));
  const history = (assessments.data ?? []).filter((entry) => entry.asset_id === assetId);
  return <>
    <header className="page-heading"><div><h1>Lineage & provenance</h1><p>Follow the evidence. Understand what a compromised asset could affect.</p></div><button className="button" onClick={() => { lineage.reload(); assessments.reload(); assets.reload(); }}>Refresh lineage</button></header>
    <div className="asset-toolbar"><label htmlFor="lineage-asset">Source asset</label><select id="lineage-asset" value={assetId} onChange={(event) => onAssetChange(event.target.value)} disabled={assets.loading || !assets.data?.length}><option value="" disabled>Select an asset</option>{assets.data?.map((asset) => <option key={asset.id} value={asset.id}>{asset.id} · {asset.asset_type}</option>)}</select></div>
    {assets.error && <StatusBanner tone="error" title="Asset selector unavailable" onRetry={assets.reload}>{assets.error}</StatusBanner>}
    {!assets.loading && !assets.error && !assets.data?.length && <StatusBanner title="No registered assets">Register an asset through the API before exploring lineage.</StatusBanner>}
    <Panel title="Evidence graph" subtitle="Contributor → Dataset → Model → Inference → Finding" loading={lineage.loading || assets.loading} error={lineage.error} onRetry={lineage.reload} empty={!lineage.loading && !nodes.length} emptyText={assetId ? 'No lineage nodes returned for this asset.' : 'Select an asset to inspect its evidence graph.'}>
      {lineage.data && !!nodes.length && <><LineageGraph nodes={nodes} edges={lineage.data.edges} selected={selected} onSelect={(nodeId) => setSelection({ assetId, nodeId })} />
        <div className="selected-node"><h3>Selected node</h3><code>{selected}</code><p className="muted">{selectedNode?.type ?? 'Unknown type'}{selectedNode?.orphan ? ' · Orphan / missing provenance' : ''}</p><details><summary>View node hash</summary><pre>{selectedNode?.hash || 'No hash exposed by backend.'}</pre><p className="footnote">A displayed hash is not proof that the hash or signature was verified.</p></details></div>
      </>}
    </Panel>
    <Panel title="Operational impact" subtitle="Downstream assets, excluding the selected source and findings" loading={lineage.loading} error={lineage.error} onRetry={lineage.reload} empty={!lineage.loading && !lineage.data} emptyText="Select an asset to calculate blast radius.">
      {lineage.data && <><div className="impact-summary"><div><strong>{total ? percent(affected.length / total) : 'N/A'}</strong><span>{affected.length} affected / {total} eligible assets in the returned graph</span></div><dl>{[['Datasets', 'dataset'], ['Models', 'model'], ['Inference records', 'inference']].map(([label, type]) => <div key={type}><dt>{label}</dt><dd>{affected.filter((node) => node.type === type || type === 'inference' && node.type === 'inference_record').length}</dd></div>)}</dl></div>
        <p className="footnote">Client-derived reachability for the selected node; this is graph exposure, not measured downtime or traffic loss. Source asset backend blast radius: {lineage.data.blast_radius.total} downstream assets.</p>
        {!!affected.length && <details><summary>Show affected asset IDs</summary><ul className="mono">{affected.map((node) => <li key={node.id}>{node.id} · {node.type}</li>)}</ul></details>}
      </>}
    </Panel>
    <Panel title="Provenance chain" subtitle="Hash, signature and replay state per inference record" loading={lineage.loading} error={lineage.error} onRetry={lineage.reload}>
      {lineage.data && <>{!lineage.data.provenance_records.length && <StatusBanner tone="warning" title="Verification states unavailable">The current lineage endpoint exposes node hashes, not chain records, signatures, sequence numbers or replay results. No verification is inferred.</StatusBanner>}
        {records.length ? <div className="chain-list">{records.map((record, index) => {
          const failure = [record.hash_state, record.signature_state, record.replay_state].some(failed);
          return <article key={`${record.id}-${index}`} className={`chain-record ${failure ? 'chain-failed' : ''}`}><header><h3 className="mono">{record.id}</h3><span className="muted">Sequence {record.sequence_number}</span>{failure && <span className="badge badge-error">Verification failure</span>}</header><div className="record-states"><span>Hash <State value={record.hash_state} /></span><span>Signature <State value={record.signature_state} /></span><span>Replay <State value={record.replay_state} /></span></div><dl className="hash-details"><div><dt>Record hash</dt><dd><code>{record.record_hash || 'Unavailable'}</code></dd></div><div><dt>Previous hash</dt><dd><code>{record.previous_record_hash || 'Unavailable'}</code></dd></div><div><dt>Signature</dt><dd><code>{record.signature || 'Unavailable'}</code></dd></div></dl></article>;
        })}</div> : <p className="empty-state">No inference records available. Chain integrity has not been established.</p>}</>}
    </Panel>
    <Panel title="Audit log" subtitle="Backend audit entries when available; assessment history shown separately" loading={lineage.loading} error={lineage.error} onRetry={lineage.reload}>
      {lineage.data && (lineage.data.audit_log.length ? <ol className="audit-list">{lineage.data.audit_log.map((entry, index) => <li key={entry.id || index}><time>{entry.timestamp || 'Timestamp unavailable'}</time><strong>{entry.action}</strong><State value={entry.status} /></li>)}</ol> : <p className="empty-state">The current API does not expose a dedicated audit log. Assessment history below is not a tamper-evident audit trail.</p>)}
    </Panel>
    <Panel title="Assessment history" subtitle="Most recent 200 assessments globally, filtered to this asset" loading={assessments.loading} error={assessments.error} onRetry={assessments.reload} empty={!!assessments.data && !history.length} emptyText="No assessment history returned for this asset.">
      {!!history.length && <ol className="audit-list">{history.map((entry) => <li key={entry.assessment_id}><div><time>{entry.finished_at ? new Date(entry.finished_at).toLocaleString() : 'In progress'}</time><strong className="mono">{entry.assessment_id}</strong></div><span>{entry.finding_count} findings · {entry.skipped.length} skipped checks</span><details><summary>Execution log</summary><pre>{display(entry.tier_logs)}</pre></details></li>)}</ol>}
    </Panel>
  </>;
}
