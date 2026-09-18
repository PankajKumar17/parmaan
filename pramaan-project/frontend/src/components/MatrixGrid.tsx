import type { Verdict } from '../services/api';

export const verdictTone = (verdict: string): string => verdict.toUpperCase() === 'QUARANTINE' ? 'error' : verdict.toUpperCase() === 'REVIEW' ? 'warning' : verdict.toUpperCase() === 'ACCEPT' ? 'success' : 'info';
export const band = (value: number): number => Number(value >= .3) + Number(value >= .7);
const decisions = [['ACCEPT', 'ACCEPT', 'ACCEPT'], ['ACCEPT', 'REVIEW', 'REVIEW'], ['ACCEPT', 'REVIEW', 'QUARANTINE']];
const labels = ['Low', 'Medium', 'High'];

export default function MatrixGrid({ verdicts, selected, onSelect }: { verdicts: Verdict[]; selected: string | null; onSelect: (cell: string | null) => void }) {
  return <div className="matrix-chart">
    <div className="matrix-y-label">Severity · impact if true</div>
    <div className="matrix-cells">{[2, 1, 0].map((severity) => <div className="matrix-row" key={severity}><span className="matrix-axis">{labels[severity]}</span>{[0, 1, 2].map((confidence) => {
      const id = `${severity}-${confidence}`;
      const matches = verdicts.filter((entry) => band(entry.finding.severity) === severity && band(entry.finding.confidence) === confidence);
      const verdict = decisions[severity][confidence];
      return <button type="button" key={id} className={`matrix-cell matrix-${verdictTone(verdict)} ${selected === id ? 'selected' : ''}`} aria-pressed={selected === id} aria-label={`${labels[severity]} severity, ${labels[confidence]} confidence: ${matches.length} findings. Policy: ${verdict}. Filter verdicts.`} onClick={() => onSelect(selected === id ? null : id)}><span>{verdict}</span><strong>{matches.length}</strong><small>{matches.length === 1 ? 'finding' : 'findings'}</small></button>;
    })}</div>)}<div className="matrix-row matrix-x-ticks"><span />{labels.map((label) => <span key={label}>{label}</span>)}</div></div>
    <div className="matrix-x-label">Confidence · certainty of evidence</div>
    <p className="footnote">Low &lt;0.30 · Medium 0.30–0.69 · High ≥0.70. Select a cell to inspect its verdicts. Colors show decision policy, not aggregate safety.</p>
  </div>;
}
