import { useCallback, useMemo, useState } from 'react';
import { getCoverage, getHeatmap, getMatrix, getRadar, percent, display, type Asset } from '../../services/api';
import { useApi, type ApiState } from '../../hooks/useApi';
import Panel from '../../components/Panel';
import StatusBanner from '../../components/StatusBanner';
import Heatmap from '../../components/Heatmap';
import RadarChart from '../../components/RadarChart';
import MatrixGrid, { band, verdictTone } from '../../components/MatrixGrid';

export default function Dashboard({ assets, onPassport }: { assets: ApiState<Asset[]>; onPassport: (id: string) => void }) {
  const matrix = useApi(getMatrix, { pollInterval: 60000 });
  const heatmap = useApi(getHeatmap, { pollInterval: 60000 });
  const coverage = useApi(getCoverage, { pollInterval: 60000 });
  const models = (assets.data ?? []).filter((asset) => asset.asset_type === 'MODEL');
  const [modelChoice, setModelChoice] = useState('');
  const model = models.some((asset) => asset.id === modelChoice) ? modelChoice : models[0]?.id ?? '';
  const fetchRadar = useCallback((signal: AbortSignal) => getRadar(model, signal), [model]);
  const radar = useApi(fetchRadar, { enabled: !!model, pollInterval: 60000 });
  const [cell, setCell] = useState<string | null>(null);
  const verdicts = matrix.data?.verdicts ?? [];
  const visible = cell ? verdicts.filter((entry) => `${band(entry.finding.severity)}-${band(entry.finding.confidence)}` === cell) : verdicts;
  const components = useMemo(() => {
    const values = new Map<string, number>();
    for (const { finding } of matrix.data?.verdicts ?? []) {
      const name = typeof finding.provenance.detector_id === 'string' ? finding.provenance.detector_id : 'Unknown detector';
      values.set(name, Math.min(values.get(name) ?? 1, 1 - finding.severity * finding.confidence));
    }
    return Array.from(values.entries());
  }, [matrix.data]);
  const refresh = () => { matrix.reload(); heatmap.reload(); coverage.reload(); radar.reload(); assets.reload(); };
  return <>
    <header className="page-heading"><div><h1>Evidence overview</h1><p>Decisions first. Scores are context, never a substitute for evidence.</p></div><button className="button" onClick={refresh}>Refresh evidence</button></header>
    <Panel title="Risk decision matrix" subtitle="Latest assessment · severity and confidence remain separate" className="primary-panel" loading={matrix.loading} error={matrix.error} onRetry={matrix.reload} actions={<span className="badge badge-info">Primary decision surface</span>}>
      {matrix.data && <><div className="matrix-layout"><MatrixGrid verdicts={verdicts} selected={cell} onSelect={setCell} /><div className="decision-context"><h3>Read the decision, not a score</h3><p>Severity describes the impact if a claim is true. Confidence describes how well the evidence supports it.</p><dl><div><dt>Assessment</dt><dd className="mono">{matrix.data.assessment_id || 'None executed'}</dd></div><div><dt>Verdicts in this assessment</dt><dd>{verdicts.length}</dd></div><div><dt>Quarantine recommendations</dt><dd>{verdicts.filter((entry) => entry.verdict === 'QUARANTINE').length}</dd></div></dl><p className="footnote">Recommendations do not execute quarantine. Review scope and counter-evidence before taking operational action.</p></div></div>
      <div className="section-heading"><h3>{cell ? 'Filtered verdicts' : 'Evidence behind each verdict'}</h3>{cell && <button className="button small" onClick={() => setCell(null)}>Clear filter</button>}</div>
      {!visible.length ? <p className="empty-state">{verdicts.length ? 'No verdicts in this matrix cell.' : 'No findings in the latest assessment. This is not an acceptance or safety determination.'}</p> : <div className="verdict-list">{visible.map((entry, index) => <article className="verdict" key={`${entry.finding.asset_id}-${entry.finding.finding_type}-${index}`}>
        <header><span className={`badge badge-${verdictTone(entry.verdict)}`}>{entry.verdict}</span><h4>{entry.finding.finding_type.replace(/_/g, ' ')}</h4><button className="button small" onClick={() => onPassport(entry.finding.asset_id)}>Open passport</button></header>
        <div className="verdict-meta"><span>Severity <strong>{percent(entry.finding.severity)}</strong></span><span>Confidence <strong>{percent(entry.finding.confidence)}</strong></span><span>Scope <strong>{entry.quarantine_scope}</strong></span><span className="mono">{entry.scope_asset_id || entry.finding.asset_id}</span></div>
        <div className="evidence-columns"><div><h5>Supporting evidence</h5>{entry.evidence.length ? <ul>{entry.evidence.map((item, i) => <li key={i}>{display(item)}</li>)}</ul> : <p className="muted">Not provided.</p>}</div><div><h5>Counter-evidence</h5>{entry.counter_evidence.length ? <ul>{entry.counter_evidence.map((item, i) => <li key={i}>{display(item)}</li>)}</ul> : <p className="warning-text">Not provided. Absence is not confirmation.</p>}</div></div>
        {entry.scope_note && <p className="footnote">{entry.scope_note}</p>}{entry.warning && <StatusBanner tone="warning" title="Decision requires review">{entry.warning}</StatusBanner>}
      </article>)}</div>}</>}
    </Panel>
    <div className="dashboard-grid">
      <Panel title="Contributor risk heatmap" subtitle="Observed anomaly rate in explicit batch order" loading={heatmap.loading} error={heatmap.error} onRetry={heatmap.reload} empty={!!heatmap.data && !heatmap.data.series.length} emptyText="No contributor history. Register contributor and batch metadata, then run an assessment.">
        {heatmap.data && !!heatmap.data.series.length && <Heatmap data={heatmap.data} />}
      </Panel>
      <Panel title="Model integrity radar" subtitle="Identity and behavioral vectors · display only" loading={radar.loading || assets.loading} error={assets.error || radar.error} onRetry={assets.error ? assets.reload : radar.reload} empty={!assets.loading && !radar.loading && (!model || !!radar.data && !radar.data.identity.length && !radar.data.behavioral.length)} emptyText={model ? 'No identity or behavioral findings for this model. Missing checks are not a clean result.' : 'No model assets registered.'} actions={<label className="compact-label">Model<select value={model} onChange={(event) => setModelChoice(event.target.value)} disabled={!models.length}><option value="" disabled>Select model</option>{models.map((asset) => <option key={asset.id} value={asset.id}>{asset.id}</option>)}</select></label>}>
        {radar.data && <RadarChart data={radar.data} />}
      </Panel>
      <Panel title="Unified trust score · decomposed only" subtitle="Triage aid—not a decision rule or probability of safety" loading={matrix.loading} error={matrix.error} onRetry={matrix.reload} empty={!!matrix.data && !components.length} emptyText="No detector components available. No trust score is inferred.">
        {!!components.length && <><div className="component-bars">{components.map(([name, value]) => <div key={name}><div className="bar-label"><span>{name}</span><strong>{percent(value)}</strong></div><svg viewBox="0 0 400 10" role="img" aria-label={`${name}: ${percent(value)} triage component`}><rect width="400" height="10" rx="2" className="bar-track" /><rect width={400 * value} height="10" rx="2" className="bar-value" /></svg></div>)}</div><p className="footnote">Each component = 1 − max(severity × confidence) per detector in the latest assessment. No overall rollup is shown. Unexecuted detectors are absent, not assigned full trust.</p></>}
      </Panel>
      <Panel title="Coverage & assurance debt" subtitle="Capability does not imply execution" loading={coverage.loading} error={coverage.error} onRetry={coverage.reload}>
        {coverage.data && <>
          <StatusBanner tone={!coverage.data.execution_verified || coverage.data.assurance_debt.length ? 'warning' : 'info'} title={`${percent(coverage.data.coverage_confidence)} requested-check coverage`}>{coverage.data.ran.length} of {coverage.data.requested.length} requested checks ran. {coverage.data.execution_verified ? 'Execution recorded by backend.' : 'Execution not verified.'}</StatusBanner>
          <h3 className="subheading">Access-level capability matrix</h3><p className="footnote">Current access: <strong>{coverage.data.access_matrix.access_level.replace(/_/g, ' ')}</strong>. Eligibility below is not a detector execution log.</p>
          {coverage.data.access_matrix.checks.length ? <div className="table-scroll"><table><thead><tr><th>Check</th><th>Capability</th><th>Eligibility</th></tr></thead><tbody>{coverage.data.access_matrix.checks.map((check, index) => <tr key={`${check.check}-${index}`}><th scope="row">{check.check}<small className="muted">{check.reason}</small></th><td>{check.capability || 'Unknown'}</td><td><span className={`badge badge-${check.status === 'ran' ? 'info' : 'warning'}`}>{check.status === 'ran' ? 'Eligible' : check.status || 'Unknown'}</span></td></tr>)}</tbody></table></div> : <p className="empty-state">Capability matrix unavailable.</p>}
          <h3 className="subheading">Assurance debt <span className="muted">({coverage.data.assurance_debt.length})</span></h3>
          {coverage.data.assurance_debt.length ? <ul className="debt-list">{coverage.data.assurance_debt.map((gap, index) => <li key={index}><strong>{gap.check}</strong><p>{gap.gap}</p><small>{gap.recommendation}</small></li>)}</ul> : <p className="muted">No assurance debt reported; coverage is not proof of safety.</p>}
        </>}
      </Panel>
    </div>
  </>;
}
