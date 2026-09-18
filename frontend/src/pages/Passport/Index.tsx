import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { assess, errorMessage, exportPassport, getAsset, getPassport, type Asset, type JsonObject } from '../../services/api';
import { useApi, type ApiState } from '../../hooks/useApi';
import Panel from '../../components/Panel';
import StatusBanner from '../../components/StatusBanner';
import StalenessBadge from '../../components/StalenessBadge';

function MarkdownPreview({ markdown }: { markdown: string }) {
  return <div className="markdown-preview">{markdown.split('\n').map((line, index) => {
    if (line.startsWith('### ')) return <h4 key={index}>{line.slice(4)}</h4>;
    if (line.startsWith('## ')) return <h3 key={index}>{line.slice(3)}</h3>;
    if (line.startsWith('# ')) return <h2 key={index}>{line.slice(2)}</h2>;
    if (line.startsWith('- ')) return <p key={index} className="markdown-item">{line.slice(2)}</p>;
    return line.trim() ? <p key={index}>{line}</p> : null;
  })}</div>;
}

export default function Passport({ assets, assetId, onAssetChange }: { assets: ApiState<Asset[]>; assetId: string; onAssetChange: (id: string) => void }) {
  const fetchPassport = useCallback((signal: AbortSignal) => getPassport(assetId, signal), [assetId]);
  const fetchMarkdown = useCallback((signal: AbortSignal) => exportPassport(assetId, 'markdown', signal), [assetId]);
  const fetchAsset = useCallback((signal: AbortSignal) => getAsset(assetId, signal), [assetId]);
  const passport = useApi(fetchPassport, { enabled: !!assetId, pollInterval: 60000 });
  const markdown = useApi(fetchMarkdown, { enabled: !!assetId, pollInterval: 60000 });
  const asset = useApi(fetchAsset, { enabled: !!assetId });
  const [payload, setPayload] = useState('');
  const [busy, setBusy] = useState<'assess' | 'markdown' | 'json' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState('');
  const operation = useRef<AbortController | null>(null);
  useEffect(() => {
    setPayload(''); setError(null); setSuccess(''); setBusy(null);
    return () => { operation.current?.abort(); operation.current = null; };
  }, [assetId]);
  const refresh = () => { passport.reload(); markdown.reload(); asset.reload(); };
  async function runAssessment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!assetId || busy) return;
    setError(null); setSuccess('');
    let parsed: JsonObject | undefined;
    try {
      if (payload.trim()) {
        const value: unknown = JSON.parse(payload, (_key: string, value: unknown) => {
          if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('Payload numbers must be finite.');
          return value;
        });
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Payload must be a JSON object, not an array or primitive.');
        if (new TextEncoder().encode(JSON.stringify(value)).byteLength > 2000000) throw new Error('Payload exceeds the 2 MB limit.');
        parsed = value as JsonObject;
      }
    } catch (error) { setError(error instanceof SyntaxError ? 'Invalid JSON. Check quotes, commas and brackets before assessing.' : errorMessage(error)); return; }
    const controller = new AbortController(); operation.current = controller;
    setBusy('assess');
    try {
      const result = await assess(assetId, parsed, controller.signal);
      if (controller.signal.aborted) return;
      setSuccess(`Assessment ${result.assessment_id} completed: ${result.finding_count} findings, ${result.skipped.length} skipped checks. Review coverage before interpreting results.`);
      refresh();
    } catch (error) {
      if (!controller.signal.aborted) setError(`${errorMessage(error)} The server may still be processing; inspect assessment history before retrying.`);
    } finally { if (!controller.signal.aborted) { setBusy(null); operation.current = null; } }
  }
  async function download(format: 'markdown' | 'json') {
    if (!assetId || busy) return;
    const controller = new AbortController(); operation.current = controller;
    setBusy(format); setError(null); setSuccess('');
    try {
      const content = await exportPassport(assetId, format, controller.signal);
      if (controller.signal.aborted) return;
      const url = URL.createObjectURL(new Blob([content], { type: format === 'json' ? 'application/json' : 'text/markdown;charset=utf-8' }));
      const link = document.createElement('a');
      link.href = url; link.download = `pramaan-${assetId.replace(/[^a-zA-Z0-9_.-]/g, '_')}.${format === 'json' ? 'json' : 'md'}`;
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setSuccess(`${format === 'json' ? 'JSON' : 'Markdown'} export downloaded with backend staleness information.`);
    } catch (error) { if (!controller.signal.aborted) setError(errorMessage(error)); }
    finally { if (!controller.signal.aborted) { setBusy(null); operation.current = null; } }
  }
  return <>
    <header className="page-heading"><div><h1>Assurance passport</h1><p>Portable findings, scoped dispositions and explicit limitations.</p></div><button className="button" onClick={refresh} disabled={!assetId || !!busy}>Check freshness</button></header>
    <div className="asset-toolbar"><label htmlFor="passport-asset">Asset</label><select id="passport-asset" value={assetId} onChange={(event) => onAssetChange(event.target.value)} disabled={!!busy || assets.loading || !assets.data?.length}><option value="" disabled>Select an asset</option>{assets.data?.map((item) => <option key={item.id} value={item.id}>{item.id} · {item.asset_type}</option>)}</select><div className="export-actions"><button className="button" disabled={!assetId || !!busy} onClick={() => void download('markdown')}>{busy === 'markdown' ? 'Exporting…' : 'Export Markdown'}</button><button className="button" disabled={!assetId || !!busy} onClick={() => void download('json')}>{busy === 'json' ? 'Exporting…' : 'Export JSON'}</button></div></div>
    {assets.error && <StatusBanner tone="error" title="Asset selector unavailable" onRetry={assets.reload}>{assets.error}</StatusBanner>}
    {!assets.loading && !assets.error && !assets.data?.length && <StatusBanner title="No assets registered">Register an asset through POST /api/assets to create an assurance passport.</StatusBanner>}
    {error && <StatusBanner tone="error" title="Action failed">{error}</StatusBanner>}{success && <StatusBanner tone="info" title="Action completed">{success}</StatusBanner>}
    <Panel title="Asset & issuance status" loading={asset.loading || passport.loading} error={asset.error} onRetry={asset.reload} empty={!assetId} emptyText="Select an asset to view its issuance status.">
      {assetId && <>{asset.data && <dl className="asset-details"><div><dt>Asset type</dt><dd>{asset.data.asset_type}</dd></div><div><dt>Manifest hash</dt><dd><code>{asset.data.manifest_hash || 'Unavailable'}</code></dd></div><div><dt>Passport issued</dt><dd>{passport.data?.issued_at ? new Date(passport.data.issued_at).toLocaleString() : 'Not available'}</dd></div></dl>}
      {passport.error && <StatusBanner tone="error" title="Passport status unavailable" onRetry={passport.reload}>{passport.error}</StatusBanner>}<StalenessBadge staleness={passport.error ? undefined : passport.data?.staleness} /><p className="footnote">Freshness is the backend’s last reported state, refreshed every minute. Signature verification is performed server-side, not by this browser.</p></>}
    </Panel>
    <Panel title="Run an assessment" subtitle="Assess the selected asset using registered inputs or an optional JSON payload">
      <form onSubmit={runAssessment} className="assessment-form" aria-busy={busy === 'assess'}><label htmlFor="assessment-payload">Optional payload (JSON object)</label><textarea id="assessment-payload" className="mono" rows={7} value={payload} onChange={(event) => setPayload(event.target.value)} placeholder="{}" disabled={!!busy || !assetId} spellCheck={false} aria-describedby="payload-help" /><p id="payload-help" className="footnote">Leave blank to use registered inputs. Model paths, runtimes and access levels must be registered server-side. Missing inputs appear as skipped checks, not passed checks.</p><button className="button primary" type="submit" disabled={!assetId || !!busy}>{busy === 'assess' ? 'Assessment running…' : 'Assess asset'}</button><span className="muted">Assessment may take several minutes. Do not submit twice.</span></form>
    </Panel>
    <div className="passport-grid"><Panel title="Passport JSON" loading={passport.loading} error={passport.error} onRetry={passport.reload} empty={!assetId || !!passport.data && !Object.keys(passport.data.document).length} emptyText="No passport available. Select an asset and run an assessment.">{passport.data && <pre className="json-view" tabIndex={0}>{JSON.stringify(passport.data.document, null, 2)}</pre>}</Panel>
      <Panel title="Markdown preview" subtitle="Safe text rendering; embedded HTML and links are not executed" loading={markdown.loading} error={markdown.error} onRetry={markdown.reload} empty={!assetId || markdown.data === ''} emptyText="No markdown passport available.">{markdown.data && <MarkdownPreview markdown={markdown.data} />}</Panel></div>
  </>;
}
