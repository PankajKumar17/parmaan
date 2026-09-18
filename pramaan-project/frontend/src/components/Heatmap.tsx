import type { HeatmapData } from '../services/api';
import { percent } from '../services/api';
import Sparkline from './Sparkline';

export default function Heatmap({ data }: { data: HeatmapData }) {
  const batches = Array.from(new Set(data.series.flatMap((row) => row.batches.map((batch) => batch.batch_id))));
  return <>
    <div className="table-scroll"><table className="heatmap-table"><caption className="sr-only">Contributor anomaly rates by batch; missing observations are not scored.</caption>
      <thead><tr><th scope="col">Contributor</th>{batches.map((batch) => <th key={batch} scope="col" title={batch}>{batch}</th>)}<th scope="col">Anomaly trend</th></tr></thead>
      <tbody>{data.series.map((row) => {
        const point = data.change_points.find((point) => point.contributor_id === row.contributor_id);
        const changeIndex = row.batches.findIndex((batch) => batch.batch_id === point?.change_point_batch);
        return <tr key={row.contributor_id}><th scope="row" className="mono">{row.contributor_id}</th>
          {batches.map((id) => {
            const batch = row.batches.find((batch) => batch.batch_id === id);
            const value = batch?.anomaly_rate;
            return <td key={id}><div className={`heat-cell ${value === undefined ? 'heat-missing' : value >= .7 ? 'heat-high' : value >= .3 ? 'heat-medium' : 'heat-low'} ${point?.change_point_batch === id ? 'heat-change' : ''}`} title={batch ? `${id}: ${percent(batch.anomaly_rate)} anomaly rate, ${batch.sample_count} samples${point?.change_point_batch === id ? ', change point' : ''}` : 'No samples in this batch'}>{value === undefined ? '—' : percent(value)}</div></td>;
          })}
          <td><Sparkline values={row.sparkline} changePoint={changeIndex} label={`${row.contributor_id} anomaly trend`} />{point && <small className="warning-text">Change: {point.change_point_batch}</small>}</td>
        </tr>;
      })}</tbody>
    </table></div>
    <div className="legend"><span><i className="key key-success" />Low &lt;30%</span><span><i className="key key-warning" />30–69%</span><span><i className="key key-error" />High ≥70%</span><span>Dashed marker: change point</span></div>
    <p className="footnote">Metadata coverage: {percent(data.metadata_coverage)} · {data.missing_metadata.length} missing metadata · {data.unmatched_findings.length} unmatched findings. No anomalies does not establish safety.</p>
  </>;
}
