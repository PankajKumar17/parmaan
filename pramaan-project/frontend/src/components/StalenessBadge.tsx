import type { Staleness } from '../services/api';

export default function StalenessBadge({ staleness }: { staleness?: Staleness }) {
  const state = staleness?.stale;
  return <div className="staleness">
    <span className={`badge ${state === true ? 'badge-error' : state === false ? 'badge-success' : 'badge-warning'}`}>
      {state === true ? 'Stale / invalidated' : state === false ? 'Fresh at last check' : 'Freshness unverified'}
    </span>
    {staleness?.checked_at && <span className="muted">Checked {new Date(staleness.checked_at).toLocaleString()}</span>}
    {!!staleness?.reasons.length && <ul>{staleness.reasons.map((reason, index) => <li key={index}>{reason}</li>)}</ul>}
  </div>;
}
