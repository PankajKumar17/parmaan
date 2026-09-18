import type { RadarData } from '../services/api';
import { percent } from '../services/api';

export default function RadarChart({ data }: { data: RadarData }) {
  const groups = [{ name: 'Identity', values: data.identity, className: 'radar-identity' }, { name: 'Behavioral', values: data.behavioral, className: 'radar-behavioral' }];
  const axes = Array.from(new Set([...data.identity, ...data.behavioral].map((value) => value.detector)));
  const count = Math.max(3, axes.length);
  const point = (index: number, radius: number) => {
    const angle = index * Math.PI * 2 / count - Math.PI / 2;
    return { x: 200 + Math.cos(angle) * radius, y: 165 + Math.sin(angle) * radius };
  };
  const polygon = (radius: number) => Array.from({ length: count }, (_, index) => { const p = point(index, radius); return `${p.x},${p.y}`; }).join(' ');
  return <>
    <svg viewBox="0 0 400 340" className="radar" role="img" aria-label="Detector severity radar. Identity and behavioral findings shown separately. Higher values mean greater severity, not greater trust.">
      {[.25, .5, .75, 1].map((level) => <g key={level}><polygon points={polygon(level * 108)} className="radar-ring" /><text x="206" y={165 - level * 108} className="chart-tick">{percent(level)}</text></g>)}
      {Array.from({ length: count }, (_, index) => {
        const p = point(index, 108);
        const label = point(index, 138);
        const name = axes[index];
        return <g key={index}><line x1="200" y1="165" x2={p.x} y2={p.y} className="chart-guide" /><text x={label.x} y={label.y} textAnchor="middle" className="chart-label"><title>{name ?? 'Unmeasured axis'}</title>{name ? name.length > 22 ? `${name.slice(0, 20)}…` : name : 'Unmeasured'}</text></g>;
      })}
      {groups.map((group) => {
        const values = axes.map((axis, index) => {
          const value = group.values.find((entry) => entry.detector === axis);
          return value ? { ...point(index, value.severity * 108), value } : null;
        });
        const complete = axes.length >= 3 && values.every((value) => value !== null);
        return <g key={group.name} className={group.className}>
          {complete && <polygon points={values.map((value) => value ? `${value.x},${value.y}` : '').join(' ')} className="radar-area" />}
          {values.map((value, index) => value && <g key={index}>{!complete && <line x1="200" y1="165" x2={value.x} y2={value.y} stroke="currentColor" strokeWidth="2" />}<circle cx={value.x} cy={value.y} r="4" fill="currentColor"><title>{group.name}: {value.value.detector}, severity {percent(value.value.severity)}, confidence {percent(value.value.confidence)}</title></circle></g>)}
        </g>;
      })}
    </svg>
    <div className="legend"><span><i className="key key-accent" />Identity</span><span><i className="key key-behavioral" />Behavioral</span></div>
    <p className="footnote">Radial scale: severity, 0–100%. Missing axes are unmeasured, never zero-filled. Polygons require at least three complete axes per vector.</p>
    <div className="table-scroll"><table><thead><tr><th>Detector / vector</th><th>Severity</th><th>Confidence</th></tr></thead><tbody>{groups.flatMap((group) => group.values.map((value) => <tr key={`${group.name}-${value.detector}`}><th scope="row">{value.detector}<small className="muted">{group.name} · {value.finding_count} findings</small></th><td>{percent(value.severity)}</td><td>{percent(value.confidence)}</td></tr>))}</tbody></table></div>
  </>;
}
