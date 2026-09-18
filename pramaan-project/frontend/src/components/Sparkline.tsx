export default function Sparkline({ values, changePoint, label = 'Anomaly rate by batch', height = 42 }: { values: number[]; changePoint?: number; label?: string; height?: number }) {
  if (!values.length) return <span className="muted">No history</span>;
  const x = (index: number) => values.length === 1 ? 80 : 5 + index * 150 / (values.length - 1);
  const y = (value: number) => height - 5 - Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0)) * (height - 10);
  const points = values.map((value, index) => `${x(index)},${y(value)}`).join(' ');
  const cp = changePoint !== undefined && changePoint >= 0 && changePoint < values.length ? changePoint : undefined;
  return <svg className="sparkline" viewBox={`0 0 160 ${height}`} role="img" aria-label={`${label}. Values: ${values.map((value) => `${Math.round(value * 100)}%`).join(', ')}${cp !== undefined ? `. Change point at batch ${cp + 1}.` : ''}`}>
    <line x1="5" y1={height - 5} x2="155" y2={height - 5} className="chart-guide" />
    <polyline points={points} fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
    {values.length === 1 && <circle cx="80" cy={y(values[0])} r="3" fill="currentColor" />}
    {cp !== undefined && <g className="change-point"><line x1={x(cp)} x2={x(cp)} y1="2" y2={height - 2} stroke="currentColor" strokeDasharray="3 3" /><circle cx={x(cp)} cy={y(values[cp])} r="3" fill="currentColor" /></g>}
  </svg>;
}
