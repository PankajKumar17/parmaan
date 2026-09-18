import axios from 'axios';

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };
export interface User { id: string; email: string; is_active: boolean }
export interface AssetInput { id: string; asset_type: 'DATASET' | 'MODEL' | 'CONTRIBUTOR'; manifest_hash: string }
export interface Asset extends AssetInput { created_at: string }
export interface Integrity { status: string; verified: boolean; missing: string[]; changed: string[]; added: string[]; errors: string[] }
export interface Health { status: string; self_integrity: string }
export interface Finding {
  asset_id: string; finding_type: string; severity: number; confidence: number;
  evidence: Json[]; counter_evidence: Json[]; provenance: JsonObject;
  recommended_action: string; quarantine_scope: string;
}
export interface Verdict {
  finding: Finding; verdict: string; quarantine_scope: string; scope_asset_id: string;
  evidence: Json[]; counter_evidence: Json[]; scope_note: string; warning: string;
}
export interface Matrix { assessment_id: string; verdicts: Verdict[] }
export interface Batch { batch_id: string; anomaly_rate: number; sample_count: number }
export interface HeatmapSeries { contributor_id: string; batches: Batch[]; sparkline: number[] }
export interface ChangePoint { contributor_id: string; change_point_batch: string; before_rate: number; after_rate: number }
export interface HeatmapData {
  series: HeatmapSeries[]; change_points: ChangePoint[]; metadata_coverage: number;
  missing_metadata: string[]; unmatched_findings: string[];
}
export interface RadarVector { detector: string; severity: number; confidence: number; finding_count: number }
export interface RadarData { model_id: string; identity: RadarVector[]; behavioral: RadarVector[] }
export interface Gap { check: string; gap: string; recommendation: string }
export interface Capability { check: string; capability: string; status: string; reason: string }
export interface Coverage {
  assessment_id: string; requested: string[]; ran: string[]; skipped: Json[]; degraded: Json[];
  coverage_confidence: number; assurance_debt: Gap[]; execution_verified: boolean;
  access_matrix: { access_level: string; checks: Capability[] };
}
export interface Assessment {
  assessment_id: string; asset_id: string; started_at: string; finished_at: string;
  tier_logs: Json[]; skipped: Json[]; finding_count: number; timings: Record<string, number>;
}
export interface LineageNode { id: string; type: string; hash: string; orphan: boolean }
export interface LineageEdge { source: string; target: string }
export interface ProvenanceRecord {
  id: string; record_hash: string; previous_record_hash: string; signature: string;
  hash_state: string; signature_state: string; replay_state: string; sequence_number: string;
}
export interface AuditEntry { id: string; timestamp: string; action: string; status: string }
export interface BlastRadius { models: string[]; datasets: string[]; inference_records: string[]; total: number }
export interface LineageData {
  nodes: LineageNode[]; edges: LineageEdge[]; blast_radius: BlastRadius;
  provenance_records: ProvenanceRecord[]; audit_log: AuditEntry[];
}
export interface Staleness { stale: boolean | null; checked_at: string; reasons: string[] }
export interface PassportData { document: JsonObject; asset_id: string; issued_at: string; staleness: Staleness }

export const AUTH_EVENT = 'pramaan:auth-expired';
const TOKEN_KEY = 'pramaan.access_token';
export function getToken(): string | null {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}
export function clearToken(): void {
  try { localStorage.removeItem(TOKEN_KEY); } finally { window.dispatchEvent(new Event(AUTH_EVENT)); }
}
export const api = axios.create({
  baseURL: (import.meta.env.VITE_API_URL ?? 'http://localhost:8000').replace(/\/$/, ''),
  timeout: 30000,
  maxRedirects: 0,
});
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.set('Authorization', `Bearer ${token}`);
  return config;
});
api.interceptors.response.use((response) => response, (error: unknown) => {
  if (axios.isAxiosError(error) && error.response?.status === 401) clearToken();
  return Promise.reject(error);
});

export function errorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (!error.response) return 'API unreachable or request timed out. Check the backend connection and retry.';
    const detail = object(error.response.data).detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) return `Request rejected (${error.response.status}): ${detail.map((item) => text(object(item).msg, 'Invalid field')).join('; ')}`;
    return `API request failed (${error.response.status}). Please retry.`;
  }
  return error instanceof Error ? error.message : 'Unexpected error. Please retry.';
}
export function display(value: unknown): string {
  if (typeof value === 'string') return value;
  return JSON.stringify(value, null, 2) ?? 'Not provided';
}
export const percent = (value: number): string => `${Math.round(value * 100)}%`;
export function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
const text = (value: unknown, fallback = ''): string => typeof value === 'string' ? value : fallback;
const list = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const strings = (value: unknown): string[] => list(value).filter((entry): entry is string => typeof entry === 'string');
const number = (value: unknown, fallback = 0): number => typeof value === 'number' && Number.isFinite(value) ? value : fallback;
function score(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) throw new Error('API returned an invalid score; this panel cannot be interpreted.');
  return value;
}
function document(value: unknown): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('API returned an unexpected response. Please retry.');
  return value as JsonObject;
}
function collection(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error('API returned an unexpected list. Please retry.');
  return value;
}
const jsonList = (value: unknown): Json[] => list(value) as Json[];
const pathId = (id: string): string => encodeURIComponent(id);
async function get(path: string, signal?: AbortSignal): Promise<JsonObject> {
  return document((await api.get<unknown>(path, { signal })).data);
}
function asset(value: unknown): Asset {
  const row = document(value);
  if (!text(row.id) || !['DATASET', 'MODEL', 'CONTRIBUTOR'].includes(text(row.asset_type))) throw new Error('API returned an invalid asset.');
  return { id: text(row.id), asset_type: row.asset_type as Asset['asset_type'], manifest_hash: text(row.manifest_hash), created_at: text(row.created_at) };
}
function finding(value: unknown): Finding {
  const row = document(value);
  return { asset_id: text(row.asset_id), finding_type: text(row.finding_type, 'Unnamed finding'), severity: score(row.severity), confidence: score(row.confidence), evidence: jsonList(row.evidence), counter_evidence: jsonList(row.counter_evidence), provenance: object(row.provenance) as JsonObject, recommended_action: text(row.recommended_action), quarantine_scope: text(row.quarantine_scope) };
}
function assessment(value: unknown): Assessment {
  const row = document(value);
  return { assessment_id: text(row.assessment_id), asset_id: text(row.asset_id), started_at: text(row.started_at), finished_at: text(row.finished_at), tier_logs: jsonList(row.tier_logs), skipped: jsonList(row.skipped), finding_count: number(row.finding_count), timings: Object.fromEntries(Object.entries(object(row.timings)).map(([key, value]) => [key, number(value)])) };
}
export async function login(username: string, password: string): Promise<{ access_token: string }> {
  const row = document((await api.post<unknown>('/api/auth/login', new URLSearchParams({ username, password }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })).data);
  const token = text(row.access_token);
  if (!token) throw new Error('Login response did not include an access token.');
  try { localStorage.setItem(TOKEN_KEY, token); } catch { throw new Error('Browser storage is unavailable. Enable local storage to sign in.'); }
  return { access_token: token };
}
export async function getMe(signal?: AbortSignal): Promise<User> {
  const row = await get('/api/auth/me', signal);
  return { id: text(row.id), email: text(row.email), is_active: row.is_active === true };
}
export async function getAssets(signal?: AbortSignal): Promise<Asset[]> {
  const result: Asset[] = [];
  for (let offset = 0; ; offset += 200) {
    const rows = collection((await api.get<unknown>('/api/assets', { params: { offset, limit: 200 }, signal })).data).map(asset);
    result.push(...rows);
    if (rows.length < 200) return result;
  }
}
export async function createAsset(input: AssetInput): Promise<Asset> { return asset((await api.post<unknown>('/api/assets', input)).data); }
export async function getAsset(id: string, signal?: AbortSignal): Promise<Asset> { return asset(await get(`/api/assets/${pathId(id)}`, signal)); }
export async function getIntegrity(signal?: AbortSignal): Promise<Integrity> {
  const row = await get('/api/system/integrity', signal);
  return { status: text(row.status, 'UNVERIFIED'), verified: row.verified === true, missing: strings(row.missing), changed: strings(row.changed), added: strings(row.added), errors: strings(row.errors) };
}
export async function getHealth(signal?: AbortSignal): Promise<Health> {
  const row = await get('/api/health', signal);
  return { status: text(row.status, 'unknown'), self_integrity: text(row.self_integrity, 'UNVERIFIED') };
}
export async function assess(asset_id: string, payload?: JsonObject, signal?: AbortSignal): Promise<Assessment> {
  return assessment((await api.post<unknown>('/api/assess', { asset_id, ...(payload ? { payload } : {}) }, { timeout: 180000, signal })).data);
}
export async function getAssessments(signal?: AbortSignal): Promise<Assessment[]> {
  return collection((await api.get<unknown>('/api/assessments', { params: { limit: 200 }, signal })).data).map(assessment);
}
export async function getMatrix(signal?: AbortSignal): Promise<Matrix> {
  const row = await get('/api/dashboard/matrix', signal);
  return { assessment_id: text(row.assessment_id), verdicts: collection(row.verdicts).map((value) => {
    const item = document(value);
    const entry = finding(item.finding);
    return { finding: entry, verdict: text(item.verdict, 'UNKNOWN'), quarantine_scope: text(item.quarantine_scope, text(item.scope, 'Not provided')), scope_asset_id: text(item.scope_asset_id), evidence: jsonList(item.evidence ?? entry.evidence), counter_evidence: jsonList(item.counter_evidence ?? entry.counter_evidence), scope_note: text(item.scope_note), warning: text(item.warning) };
  }) };
}
export async function getHeatmap(signal?: AbortSignal): Promise<HeatmapData> {
  const row = await get('/api/dashboard/heatmap', signal);
  return { series: collection(row.series).map((value) => {
    const item = document(value);
    const batches = collection(item.batches).map((value) => { const batch = document(value); return { batch_id: text(batch.batch_id), anomaly_rate: score(batch.anomaly_rate), sample_count: number(batch.sample_count) }; });
    return { contributor_id: text(item.contributor_id), batches, sparkline: batches.map((batch) => batch.anomaly_rate) };
  }), change_points: list(row.change_points).map((value) => { const point = object(value); return { contributor_id: text(point.contributor_id), change_point_batch: text(point.change_point_batch), before_rate: score(point.before_rate), after_rate: score(point.after_rate) }; }), metadata_coverage: score(row.metadata_coverage), missing_metadata: strings(row.missing_metadata), unmatched_findings: strings(row.unmatched_findings) };
}
export async function getRadar(id: string, signal?: AbortSignal): Promise<RadarData> {
  const row = await get(`/api/dashboard/radar/${pathId(id)}`, signal);
  const vectors = (value: unknown): RadarVector[] => collection(value).map((value) => { const item = document(value); return { detector: text(item.detector), severity: score(item.severity), confidence: score(item.confidence), finding_count: number(item.finding_count) }; });
  return { model_id: text(row.model_id), identity: vectors(row.identity), behavioral: vectors(row.behavioral) };
}
export async function getCoverage(signal?: AbortSignal): Promise<Coverage> {
  const row = await get('/api/dashboard/coverage', signal);
  const access = object(row.access_matrix);
  return { assessment_id: text(row.assessment_id), requested: strings(row.requested), ran: strings(row.ran), skipped: jsonList(row.skipped), degraded: jsonList(row.degraded), coverage_confidence: score(row.coverage_confidence), execution_verified: row.execution_verified === true, assurance_debt: list(row.assurance_debt).map((value) => { const gap = object(value); return { check: text(gap.check), gap: text(gap.gap), recommendation: text(gap.recommendation) }; }), access_matrix: { access_level: text(access.access_level, 'unknown'), checks: list(access.checks).map((value) => { const check = object(value); return { check: text(check.check), capability: text(check.capability), status: text(check.status), reason: text(check.reason) }; }) } };
}
export async function getLineage(id: string, signal?: AbortSignal): Promise<LineageData> {
  const row = await get(`/api/lineage/${pathId(id)}`, signal);
  const blast = object(row.blast_radius);
  const state = (value: unknown): string => value === true ? 'verified' : value === false ? 'failed' : text(value, 'unavailable');
  return { nodes: collection(row.nodes).map((value) => { const node = document(value); return { id: text(node.id), type: text(node.type, text(node.node_type, 'unknown')).toLowerCase(), hash: text(node.hash), orphan: node.orphan === true }; }), edges: collection(row.edges ?? row.links).map((value) => { const edge = object(value); return Array.isArray(value) ? { source: text(value[0]), target: text(value[1]) } : { source: text(edge.source), target: text(edge.target) }; }), blast_radius: { models: strings(blast.models), datasets: strings(blast.datasets), inference_records: strings(blast.inference_records), total: number(blast.total) }, provenance_records: list(row.provenance_records).map((value) => { const record = object(value); return { id: text(record.id), record_hash: text(record.record_hash), previous_record_hash: text(record.previous_record_hash), signature: text(record.signature), hash_state: state(record.hash_state ?? record.hash_valid), signature_state: state(record.signature_state ?? record.signature_valid), replay_state: state(record.replay_state ?? record.replay_valid), sequence_number: String(record.sequence_number ?? '—') }; }), audit_log: list(row.audit_log).map((value) => { const entry = object(value); return { id: text(entry.id), timestamp: text(entry.timestamp), action: text(entry.action), status: text(entry.status, 'unknown') }; }) };
}
export async function getPassport(id: string, signal?: AbortSignal): Promise<PassportData> {
  const row = await get(`/api/passport/${pathId(id)}`, signal);
  const stale = object(row.staleness);
  return { document: row, asset_id: text(row.asset_id), issued_at: text(row.issued_at), staleness: { stale: typeof stale.stale === 'boolean' ? stale.stale : null, checked_at: text(stale.checked_at), reasons: strings(stale.reasons) } };
}
export async function exportPassport(id: string, format: 'markdown' | 'json', signal?: AbortSignal): Promise<string> {
  const response = await api.get<string>(`/api/passport/${pathId(id)}/export`, { params: { format }, responseType: 'text', transformResponse: [(data: string) => data], signal });
  if (typeof response.data !== 'string') throw new Error('Unexpected export response.');
  return response.data;
}
