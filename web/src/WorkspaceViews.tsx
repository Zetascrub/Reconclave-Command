import { useMemo, useState } from 'react'
import type { Approval, ArchivedJob, AutomationRule, DistributedScan, EvidenceRecord, Finding, FindingStatus, FleetNode, OperatorRole, OtaRelease, OtaRollout, Project, PublicOperator, ReconNode, Workflow, WorkflowRun, WorkspaceData } from './types'
import WorkflowBuilder from './WorkflowBuilder'

type View = 'jobs' | 'projects' | 'evidence' | 'map' | 'automations' | 'workflows' | 'scopes' | 'findings' | 'timeline' | 'fleet' | 'distributed' | 'operators'

const FINDING_STATUSES: FindingStatus[] = ['open', 'candidate', 'confirmed-observed', 'confirmed', 'false_positive', 'remediated']

function stamp(value: number) { return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) }

// Hashes and base64-encodes a firmware artifact client-side so the operator never has to
// compute a SHA-256 by hand: fleet_manager.create_release re-hashes the decoded bytes
// server-side and rejects a mismatch regardless, this just gets it right the first time.
// Chunked to avoid String.fromCharCode's argument-count ceiling on a multi-hundred-KB-to-
// multi-MB image.
async function readArtifactFile(file: File): Promise<{ base64: string; sha256: string }> {
  const buffer = await file.arrayBuffer()
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  const sha256 = Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('')
  const bytes = new Uint8Array(buffer)
  let binary = ''
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize))
  }
  return { base64: btoa(binary), sha256 }
}

export default function WorkspaceViews({ view, workspace, nodes, projectId, onProject, onCreate, onInspect, onCreateAutomation, onUpdateAutomation, onDeleteAutomation, onCreateWorkflow, onRunWorkflow, onCancelWorkflow, onUpdateWorkflow, onDeleteWorkflow, onCreateScope, onImportFindings, onCorrelateFindings, onSetFindingStatus, onSetFindingSuppression, onCreateRelease, onCreateRollout, onAdvanceRollout, onRollbackRollout, onCreateDistributedScan, onCancelDistributedScan, currentOperator, onCreateOperator, onDecideApproval }:
  { view: View; workspace: WorkspaceData; nodes: ReconNode[]; projectId: string; onProject: (id: string) => void; onCreate: (name: string, description: string) => Promise<void>; onInspect: (hosts: string[], ports: number[]) => Promise<unknown>; onCreateAutomation: (body: Record<string, unknown>) => Promise<void>; onUpdateAutomation: (id: string, body: Record<string, unknown>) => Promise<void>; onDeleteAutomation: (id: string) => Promise<void>; onCreateWorkflow: (body: Record<string, unknown>) => Promise<void>; onRunWorkflow: (id: string) => Promise<void>; onCancelWorkflow: (id: string) => Promise<void>; onUpdateWorkflow: (id: string, body: Record<string, unknown>) => Promise<void>; onDeleteWorkflow: (id: string) => Promise<void>; onCreateScope: (body: Record<string, unknown>) => Promise<void>; onImportFindings: (body: Record<string, unknown>) => Promise<void>; onCorrelateFindings: () => Promise<unknown>; onSetFindingStatus: (id: string, status: FindingStatus) => Promise<void>; onSetFindingSuppression: (id: string, suppressed: boolean, reason: string) => Promise<void>; onCreateRelease: (body: Record<string, unknown>) => Promise<void>; onCreateRollout: (body: Record<string, unknown>) => Promise<void>; onAdvanceRollout: (id: string) => Promise<void>; onRollbackRollout: (id: string) => Promise<void>; onCreateDistributedScan: (body: Record<string, unknown>) => Promise<void>; onCancelDistributedScan: (id: string) => Promise<void>; currentOperator: PublicOperator | null; onCreateOperator: (body: Record<string, unknown>) => Promise<void>; onDecideApproval: (id: string, decision: 'approved' | 'rejected') => Promise<void> }) {
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState<'newest' | 'oldest' | 'name'>('newest')
  const [graph, setGraph] = useState(true)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [selectedHosts, setSelectedHosts] = useState<string[]>([])
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRecord | null>(null)
  const [ports, setPorts] = useState('22, 53, 80, 443, 445, 1883, 8080, 8443')
  const [authorised, setAuthorised] = useState(false)
  const [inspecting, setInspecting] = useState(false)
  const [inspectionError, setInspectionError] = useState('')
  const [ruleNode, setRuleNode] = useState('')
  const [ruleCondition, setRuleCondition] = useState<'dhcp_assigned' | 'internet_possible'>('dhcp_assigned')
  const [rulePlaybook, setRulePlaybook] = useState<'network_scout' | 'system_snapshot'>('system_snapshot')
  const [ruleInterval, setRuleInterval] = useState(0)
  const [ruleAuthorised, setRuleAuthorised] = useState(false)
  const [ruleError, setRuleError] = useState('')
  const [scopeNetwork, setScopeNetwork] = useState('192.168.1.0/24')
  const [scopeExclusions, setScopeExclusions] = useState('')
  const [scopeDays, setScopeDays] = useState(7)
  const [scopeApproved, setScopeApproved] = useState(false)
  const [scopeError, setScopeError] = useState('')
  const [importFormat, setImportFormat] = useState<'nessus' | 'nasl'>('nessus')
  const [importContent, setImportContent] = useState('')
  const [importError, setImportError] = useState('')
  const [correlating, setCorrelating] = useState(false)
  const [correlateError, setCorrelateError] = useState('')
  const [findingError, setFindingError] = useState('')
  const [viewTime] = useState(() => Date.now())
  const project = workspace.projects.find((item) => item.id === projectId)
  const jobs = useMemo(() => workspace.jobs.filter((item) => !projectId || item.project_id === projectId), [workspace.jobs, projectId])
  const evidence = useMemo(() => workspace.evidence.filter((item) => !projectId || item.project_id === projectId), [workspace.evidence, projectId])
  const filterSort = <T extends { title?: string; name?: string; created_at_ms?: number; captured_at_ms?: number }>(items: T[]) => items.filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase())).sort((a, b) => {
    if (sort === 'name') return (a.title ?? a.name ?? '').localeCompare(b.title ?? b.name ?? '')
    const av = a.captured_at_ms ?? a.created_at_ms ?? 0; const bv = b.captured_at_ms ?? b.created_at_ms ?? 0
    return sort === 'newest' ? bv - av : av - bv
  })
  const hosts = [...new Set(evidence.flatMap((item) => (item.data?.hosts ?? []).map((host) => typeof host === 'string' ? host : host.address)))]
  const mapped = [...nodes.map((node) => ({ id: node.device_id, address: node.address, label: node.device_type, sub: node.address, live: true, node })), ...hosts.filter((host) => !nodes.some((node) => node.address === host)).map((host) => ({ id: host, address: host, label: host, sub: 'observed', live: false }))]
  const selectedHost = selectedHosts.length === 1 ? mapped.find((item) => item.address === selectedHosts[0]) : undefined
  const hostEvidence = selectedHost ? evidence.filter((item) => item.data?.hosts?.some((host) => (typeof host === 'string' ? host : host.address) === selectedHost.address)) : []
  const title = view === 'projects' ? 'Project registry' : view === 'jobs' ? 'Operation history' : view === 'evidence' ? 'Evidence library' : view === 'automations' ? 'Conditional operations' : view === 'workflows' ? 'Workflow automation' : view === 'scopes' ? 'Engagement authority' : view === 'findings' ? 'Vulnerability analysis' : view === 'timeline' ? 'Operations audit timeline' : view === 'fleet' ? 'Fleet management' : view === 'distributed' ? 'Distributed scanning' : view === 'operators' ? 'Operators and approvals' : 'Project network map'

  return <>
    <section className="hero"><div><p className="eyebrow">PROJECT INTELLIGENCE</p><h1>{title}</h1><p className="subhead">{project ? project.name : 'All authorised project workspaces'}</p></div></section>
    <section className="workspace-toolbar panel">
      <label><span>PROJECT</span><select value={projectId} onChange={(event) => onProject(event.target.value)}><option value="">All projects</option>{workspace.projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label className="workspace-search"><span>FILTER</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search records…" /></label>
      <label><span>SORT</span><select value={sort} onChange={(event) => setSort(event.target.value as typeof sort)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="name">Name</option></select></label>
      {view === 'map' && <div className="segmented"><button className={graph ? 'active' : ''} onClick={() => setGraph(true)}>GRAPH</button><button className={!graph ? 'active' : ''} onClick={() => setGraph(false)}>LIST</button></div>}
    </section>
    {view === 'projects' && <section className="catalog-layout">
      <div className="panel create-card"><span className="kicker">NEW ENGAGEMENT</span><h2>Create project</h2><label className="field"><span>PROJECT NAME</span><input value={name} onChange={(e) => setName(e.target.value)} /></label><label className="field"><span>DESCRIPTION</span><input value={description} onChange={(e) => setDescription(e.target.value)} /></label><button className="primary-action" disabled={!name.trim()} onClick={async () => { await onCreate(name, description); setName(''); setDescription('') }}>CREATE PROJECT</button></div>
      <RecordGrid empty="No projects yet. Create the first authorised workspace.">{filterSort(workspace.projects).map((item: Project) => <article className="record-card" key={item.id} onClick={() => onProject(item.id)}><span className="record-icon">◇</span><div><span className="kicker">PROJECT</span><h3>{item.name}</h3><p>{item.description || 'No description'}</p><small>{workspace.jobs.filter((job) => job.project_id === item.id).length} jobs · {workspace.evidence.filter((ev) => ev.project_id === item.id).length} evidence · {stamp(item.created_at_ms)}</small></div></article>)}</RecordGrid>
    </section>}
    {view === 'jobs' && <RecordGrid empty="No jobs recorded for this project.">{filterSort(jobs).map((item: ArchivedJob) => <article className="record-card" key={item.id}><span className="record-icon">◫</span><div><span className="kicker">{item.capability ?? 'OPERATION'}</span><h3>{item.id}</h3><p>{item.provider_id} · {item.checked ?? 0}/{item.total ?? 0} checked · {item.hosts?.length ?? 0} hosts</p><small>{stamp(item.updated_at_ms)}</small></div><span className={`status-pill ${item.status}`}><i />{item.status}</span></article>)}</RecordGrid>}
    {view === 'evidence' && <RecordGrid empty="No evidence collected for this project.">{filterSort(evidence).map((item: EvidenceRecord) => <button className="record-card evidence-card" key={item.id} onClick={() => setSelectedEvidence(item)}><span className="record-icon">▱</span><div><span className="kicker">{item.kind}</span><h3>{item.title}</h3><p>{item.summary}</p><small>{item.job_id} · {stamp(item.captured_at_ms)}</small></div><span className="count">{item.data?.hosts?.length ?? 1}</span></button>)}</RecordGrid>}
    {view === 'automations' && <section className="catalog-layout automation-layout"><div className="panel create-card"><span className="kicker">SAFE PLAYBOOK</span><h2>Arm condition</h2><label className="field"><span>NODE</span><select value={ruleNode} onChange={(event) => setRuleNode(event.target.value)}><option value="">Select a capable node</option>{nodes.filter((node) => !node.local && (ruleCondition !== 'internet_possible' || node.capabilities.includes('net.connectivity.check')) && (rulePlaybook !== 'network_scout' || node.capabilities.includes('net.discovery.scan'))).map((node) => <option value={node.device_id} key={node.device_id}>{node.device_type} · {node.address}</option>)}</select></label><label className="field"><span>WHEN</span><select value={ruleCondition} onChange={(event) => { setRuleCondition(event.target.value as typeof ruleCondition); setRuleNode('') }}><option value="dhcp_assigned">DHCP address assigned</option><option value="internet_possible">Internet access possible</option></select></label><label className="field"><span>RUN</span><select value={rulePlaybook} onChange={(event) => { setRulePlaybook(event.target.value as typeof rulePlaybook); setRuleNode('') }}><option value="system_snapshot">Capture system snapshot</option><option value="network_scout">Authorised network Scout</option></select></label>{rulePlaybook === 'network_scout' && <label className="field"><span>REPEAT SCOUT</span><select value={ruleInterval} onChange={(event) => setRuleInterval(Number(event.target.value))}><option value={0}>Once per condition edge</option><option value={60000}>Every minute</option><option value={300000}>Every 5 minutes</option><option value={900000}>Every 15 minutes</option><option value={3600000}>Every hour</option></select></label>}<label className="authorise compact"><input type="checkbox" checked={ruleAuthorised} onChange={(event) => setRuleAuthorised(event.target.checked)} /><span><strong>AUTHORISE AUTOMATION</strong><small>Only the selected built-in playbook may execute.</small></span></label>{!projectId && <div className="inspection-error">Select a project before arming a rule.</div>}{ruleError && <div className="inspection-error">{ruleError}</div>}<button className="primary-action inspect-action" disabled={!projectId || !ruleNode || !ruleAuthorised} onClick={async () => { setRuleError(''); try { await onCreateAutomation({ node_id: ruleNode, condition: ruleCondition, playbook: rulePlaybook, interval_ms: ruleInterval }); setRuleAuthorised(false) } catch (error) { setRuleError(error instanceof Error ? error.message : 'Could not arm rule') } }}>ARM RULE</button></div><RecordGrid empty="No conditional operations configured.">{filterSort(workspace.automations.filter((item) => !projectId || item.project_id === projectId)).map((item: AutomationRule) => <article className="record-card automation-card" key={item.id}><span className={`record-icon ${item.enabled ? 'live' : ''}`}>↻</span><div><span className="kicker">{item.condition.replace('_', ' ')}</span><h3>{item.playbook.replace('_', ' ')}</h3><p>{item.node_id}{item.interval_ms ? ` · repeats every ${Math.round(item.interval_ms / 60000)}m` : ' · edge triggered'}</p><small>{item.last_triggered_ms ? `Last fired ${stamp(item.last_triggered_ms)}` : 'Waiting for condition'}{item.last_error ? ` · ${item.last_error}` : ''}</small></div><div className="rule-actions"><button onClick={() => onUpdateAutomation(item.id, { enabled: !item.enabled })}>{item.enabled ? 'PAUSE' : 'ENABLE'}</button><button className="danger" onClick={() => onDeleteAutomation(item.id)}>REMOVE</button></div></article>)}</RecordGrid></section>}
    {view === 'workflows' && <WorkflowView workflows={workspace.workflows.filter((item) => !projectId || item.project_id === projectId)} runs={workspace.workflow_runs.filter((item) => !projectId || item.project_id === projectId)} projectId={projectId} nodes={nodes} onCreateWorkflow={onCreateWorkflow} onUpdateWorkflow={onUpdateWorkflow} onRun={onRunWorkflow} onCancel={onCancelWorkflow} onDelete={onDeleteWorkflow} />}
    {view === 'scopes' && <section className="catalog-layout"><div className="panel create-card"><span className="kicker">SIGNED AUTHORITY</span><h2>Approve scope revision</h2><label className="field"><span>INCLUDED NETWORK</span><input value={scopeNetwork} onChange={(event) => setScopeNetwork(event.target.value)} /></label><label className="field"><span>EXCLUSIONS (COMMA SEPARATED)</span><input value={scopeExclusions} onChange={(event) => setScopeExclusions(event.target.value)} /></label><label className="field"><span>VALID FOR</span><select value={scopeDays} onChange={(event) => setScopeDays(Number(event.target.value))}><option value={1}>1 day</option><option value={7}>7 days</option><option value={14}>14 days</option><option value={30}>30 days</option></select></label><label className="authorise compact"><input type="checkbox" checked={scopeApproved} onChange={(event) => setScopeApproved(event.target.checked)} /><span><strong>APPROVE THIS ENGAGEMENT BOUNDARY</strong><small>A new immutable revision will be signed locally.</small></span></label>{scopeError && <div className="inspection-error">{scopeError}</div>}<button className="primary-action" disabled={!projectId || !scopeNetwork || !scopeApproved} onClick={async () => { setScopeError(''); try { await onCreateScope({ included_networks: [scopeNetwork], excluded_networks: scopeExclusions.split(',').map((value) => value.trim()).filter(Boolean), capability_classes: ['inventory', 'discovery', 'vulnerability'], expires_at_ms: Date.now() + scopeDays * 86400000, max_concurrency: 2, max_requests_per_minute: 60 }); setScopeApproved(false) } catch (error) { setScopeError(error instanceof Error ? error.message : 'Could not approve scope') } }}>SIGN SCOPE REVISION</button></div><RecordGrid empty="No engagement scopes approved.">{workspace.scopes.filter((item) => !projectId || item.project_id === projectId).sort((a, b) => b.revision - a.revision).map((item) => <article className="record-card" key={item.id}><span className="record-icon">⌗</span><div><span className="kicker">REVISION {item.revision} · {item.expires_at_ms > viewTime ? 'ACTIVE' : 'EXPIRED'}</span><h3>{item.included_networks.join(', ')}</h3><p>{item.excluded_networks.length ? `Excludes ${item.excluded_networks.join(', ')}` : 'No exclusions'} · {item.capability_classes.join(', ')}</p><small>Expires {stamp(item.expires_at_ms)} · signature {item.signature.slice(0, 16)}…</small></div></article>)}</RecordGrid></section>}
    {view === 'findings' && <section className="catalog-layout"><div className="panel create-card"><span className="kicker">OFFLINE IMPORT</span><h2>Nessus knowledge</h2><label className="field"><span>FORMAT</span><select value={importFormat} onChange={(event) => setImportFormat(event.target.value as typeof importFormat)}><option value="nessus">Nessus report XML</option><option value="nasl">NASL plugin metadata</option></select></label><label className="field"><span>DOCUMENT</span><textarea rows={10} value={importContent} onChange={(event) => setImportContent(event.target.value)} placeholder="Paste authorised .nessus XML or NASL metadata" /></label>{importError && <div className="inspection-error">{importError}</div>}<button className="primary-action" disabled={!projectId || !importContent.trim()} onClick={async () => { setImportError(''); try { await onImportFindings({ format: importFormat, content: importContent }); setImportContent('') } catch (error) { setImportError(error instanceof Error ? error.message : 'Import failed') } }}>IMPORT AND NORMALISE</button><div className="section-label" style={{ marginTop: 18 }}><span>LIVE CORRELATION</span><small>Deterministic - matches evidence against imported findings, never AI</small></div><p>Compares recent evidence host:port(:service) observations against imported findings: exact target+port hits on a host-bound finding become "confirmed-observed"; port/service-name text hits against offline templates become new low-confidence "candidate" findings for review.</p>{correlateError && <div className="inspection-error">{correlateError}</div>}<button className="primary-action" disabled={!projectId || correlating} onClick={async () => { setCorrelateError(''); setCorrelating(true); try { await onCorrelateFindings() } catch (error) { setCorrelateError(error instanceof Error ? error.message : 'Correlation failed') } finally { setCorrelating(false) } }}>{correlating ? 'CORRELATING…' : 'CORRELATE NOW'}</button></div><div>{findingError && <div className="inspection-error finding-list-error">{findingError}</div>}<RecordGrid empty="No vulnerability findings imported.">{workspace.findings.filter((item) => !projectId || item.project_id === projectId).sort((a, b) => b.risk_score - a.risk_score).map((item) => <FindingCard key={item.id} item={item} onSetStatus={onSetFindingStatus} onSetSuppression={onSetFindingSuppression} onError={setFindingError} />)}</RecordGrid></div></section>}
    {view === 'timeline' && <RecordGrid empty="No audited operations for this project.">{workspace.audit_events.filter((item) => !projectId || item.project_id === projectId).filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase())).sort((a, b) => b.created_at_ms - a.created_at_ms).map((item) => <article className="record-card" key={item.id}><span className="record-icon">≋</span><div><span className="kicker">{item.action}</span><h3>{item.subject_id || 'Platform event'}</h3><p>{item.outcome} · {item.actor_id ?? 'system'}</p><small>{item.trace_id ?? item.id} · {stamp(item.created_at_ms)}</small></div></article>)}</RecordGrid>}
    {/* Fleet spans the whole deployment, not one project - unlike every other view above it is
        intentionally not filtered by projectId. */}
    {view === 'fleet' && <FleetView nodes={workspace.fleet_nodes} releases={workspace.ota_releases} rollouts={workspace.ota_rollouts} onCreateRelease={onCreateRelease} onCreateRollout={onCreateRollout} onAdvanceRollout={onAdvanceRollout} onRollbackRollout={onRollbackRollout} />}
    {view === 'distributed' && <DistributedScanView scans={workspace.distributed_scans.filter((item) => !projectId || item.project_id === projectId)} nodes={nodes} onCreate={onCreateDistributedScan} onCancel={onCancelDistributedScan} />}
    {view === 'operators' && <OperatorsView operators={workspace.operators} approvals={workspace.approvals} currentOperator={currentOperator} onCreateOperator={onCreateOperator} onDecideApproval={onDecideApproval} />}
    {view === 'map' && <section className="map-layout"><div>{graph ? <NetworkGraph points={mapped} selected={selectedHosts} onSelect={(host) => setSelectedHosts((current) => current.includes(host) ? current.filter((item) => item !== host) : [...current, host])} /> : <RecordGrid empty="No mapped nodes yet.">{mapped.filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase())).map((item) => <button className={`record-card ${selectedHosts.includes(item.address) ? 'selected-record' : ''}`} key={item.id} onClick={() => setSelectedHosts((current) => current.includes(item.address) ? current.filter((host) => host !== item.address) : [...current, item.address])}><span className={`record-icon ${item.live ? 'live' : ''}`}>⌁</span><div><span className="kicker">{item.live ? 'LIVE NODE' : 'OBSERVATION'}</span><h3>{item.address}</h3><p>{item.label}</p></div><span className="selection-box">{selectedHosts.includes(item.address) ? '✓' : '+'}</span></button>)}</RecordGrid>}</div><HostInspector host={selectedHost} selected={selectedHosts} evidence={hostEvidence} project={project} ports={ports} setPorts={setPorts} authorised={authorised} setAuthorised={setAuthorised} busy={inspecting} error={inspectionError} onRun={async () => { const parsed = [...new Set(ports.split(/[\s,]+/).filter(Boolean).map(Number).filter((port) => Number.isInteger(port) && port > 0 && port <= 65535))]; setInspecting(true); setInspectionError(''); try { await onInspect(selectedHosts, parsed) } catch (error) { setInspectionError(error instanceof Error ? error.message : 'Inspection failed') } finally { setInspecting(false) } }} /></section>}
    {selectedEvidence && <div className="modal-shade" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelectedEvidence(null) }}><section className="evidence-viewer panel"><div className="modal-head"><div><span className="kicker">{selectedEvidence.kind}</span><h2>{selectedEvidence.title}</h2><p>{stamp(selectedEvidence.captured_at_ms)}</p></div><button onClick={() => setSelectedEvidence(null)}>×</button></div><p className="evidence-summary">{selectedEvidence.summary}</p><div className="evidence-meta"><span>PROJECT <strong>{workspace.projects.find((item) => item.id === selectedEvidence.project_id)?.name ?? selectedEvidence.project_id}</strong></span><span>JOB <strong>{selectedEvidence.job_id || '—'}</strong></span><span>EVIDENCE ID <strong>{selectedEvidence.id}</strong></span></div><h3>COLLECTED DATA</h3><pre>{JSON.stringify(selectedEvidence.data, null, 2)}</pre></section></div>}
  </>
}

function RecordGrid({ children, empty }: { children: React.ReactNode; empty: string }) {
  const count = Array.isArray(children) ? children.length : 1
  return <section className="record-grid">{count ? children : <div className="empty large panel"><span>∿</span><strong>{empty}</strong></div>}</section>
}

function FindingCard({ item, onSetStatus, onSetSuppression, onError }: { item: Finding; onSetStatus: (id: string, status: FindingStatus) => Promise<void>; onSetSuppression: (id: string, suppressed: boolean, reason: string) => Promise<void>; onError: (message: string) => void }) {
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const candidate = item.status === 'candidate'
  return <article className={`record-card finding-card ${item.suppressed ? 'suppressed-record' : ''}`}>
    <span className="record-icon">△</span>
    <div>
      <span className="kicker">{item.severity.toUpperCase()} · RISK {item.risk_score.toFixed(2)}{candidate ? ' · NEEDS REVIEW' : ''}</span>
      <h3>{item.title}</h3>
      <p>{item.target}{item.port ? `:${item.port}` : ''} · {item.cves.join(', ') || item.plugin_id}</p>
      <small>{item.source} · confidence {Math.round(item.confidence * 100)}%{item.provenance?.match_basis ? ` · matched on ${item.provenance.match_basis.replace(/_/g, ' ')}` : ''}{item.suppressed ? ` · suppressed: ${item.suppression_reason || 'no reason given'}` : ''}{item.remediation && item.remediation.status !== 'open' ? ` · remediation ${item.remediation.status}` : ''}</small>
    </div>
    <div className="rule-actions finding-actions">
      <select value={item.status} disabled={busy} onChange={async (event) => {
        const next = event.target.value as FindingStatus
        setBusy(true)
        try { await onSetStatus(item.id, next) } catch (error) { onError(error instanceof Error ? error.message : 'Status update failed') } finally { setBusy(false) }
      }}>{FINDING_STATUSES.map((status) => <option key={status} value={status}>{status.replace(/_/g, ' ')}</option>)}</select>
      {!item.suppressed && <input className="finding-reason" value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Suppression reason" />}
      <button disabled={busy} onClick={async () => {
        setBusy(true)
        try { await onSetSuppression(item.id, !item.suppressed, item.suppressed ? '' : reason); setReason('') } catch (error) { onError(error instanceof Error ? error.message : 'Suppression update failed') } finally { setBusy(false) }
      }}>{item.suppressed ? 'UNSUPPRESS' : 'SUPPRESS'}</button>
    </div>
  </article>
}

function WorkflowView({ workflows, runs, projectId, nodes, onCreateWorkflow, onUpdateWorkflow, onRun, onCancel, onDelete }: { workflows: Workflow[]; runs: WorkflowRun[]; projectId: string; nodes: ReconNode[]; onCreateWorkflow: (body: Record<string, unknown>) => Promise<void>; onUpdateWorkflow: (id: string, body: Record<string, unknown>) => Promise<void>; onRun: (id: string) => Promise<void>; onCancel: (id: string) => Promise<void>; onDelete: (id: string) => Promise<void> }) {
  // 'new' opens the builder for a fresh workflow; a Workflow opens it pre-populated for
  // editing; null keeps it closed. A drag-and-drop DAG editor (WorkflowBuilder.tsx)
  // replaces the old fixed-template create button and rename-only edit.
  const [builderTarget, setBuilderTarget] = useState<'new' | Workflow | null>(null)
  const [rowErrorId, setRowErrorId] = useState('')
  const [rowError, setRowError] = useState('')
  return <section className="catalog-layout workflow-layout">
    <div className="panel create-card"><span className="kicker">WORKFLOW AUTOMATION</span><h2>Build a workflow</h2><p>Chain capabilities across your fleet into a dependency graph: retries, timeouts, and per-step node targeting all live in the visual builder.</p>{!projectId && <div className="inspection-error">Select a project before creating a workflow.</div>}<button className="primary-action" disabled={!projectId} onClick={() => setBuilderTarget('new')}>+ OPEN BUILDER</button></div>
    <RecordGrid empty="No workflows configured for this project.">{workflows.map((workflow) => { const related = runs.filter((run) => run.workflow_id === workflow.id).sort((a, b) => b.updated_at_ms - a.updated_at_ms); const latest = related[0]; const active = latest && (latest.status === 'queued' || latest.status === 'running'); return <article className="record-card automation-card" key={workflow.id}><span className={`record-icon ${active ? 'live' : ''}`}>⇢</span><div><span className="kicker">{workflow.steps.length} STEP WORKFLOW</span><h3>{workflow.name}</h3><p>{workflow.steps.map((step) => step.capability).join(' → ')}</p><small>{latest ? `Latest run ${latest.status} · ${latest.steps.filter((step) => step.status === 'complete').length}/${latest.steps.length} complete · ${stamp(latest.updated_at_ms)}` : `Created ${stamp(workflow.created_at_ms)}`}</small>{latest?.steps.some((step) => step.error) && <small className="inspection-error">{latest.steps.find((step) => step.error)?.error}</small>}{rowErrorId === workflow.id && <small className="inspection-error">{rowError}</small>}</div><div className="rule-actions">
      <button disabled={Boolean(active)} onClick={() => onRun(workflow.id)}>RUN</button>
      {active && <button className="danger" onClick={() => onCancel(latest.id)}>STOP</button>}
      <button disabled={Boolean(active)} onClick={() => setBuilderTarget(workflow)}>EDIT</button>
      <button className="danger" disabled={Boolean(active)} onClick={async () => { setRowErrorId(''); try { await onDelete(workflow.id) } catch (err) { setRowErrorId(workflow.id); setRowError(err instanceof Error ? err.message : 'Delete failed') } }}>REMOVE</button>
    </div></article> })}</RecordGrid>
    {builderTarget && <WorkflowBuilder
      workflow={builderTarget === 'new' ? null : builderTarget}
      nodes={nodes}
      onClose={() => setBuilderTarget(null)}
      onSave={async (body) => {
        if (builderTarget === 'new') await onCreateWorkflow({ ...body, project_id: projectId })
        else await onUpdateWorkflow(builderTarget.id, body)
      }} />}
  </section>
}

function DistributedScanView({ scans, nodes, onCreate, onCancel }: { scans: DistributedScan[]; nodes: ReconNode[]; onCreate: (body: Record<string, unknown>) => Promise<void>; onCancel: (id: string) => Promise<void> }) {
  const [mode, setMode] = useState<'parallel' | 'consensus'>('parallel')
  const [network, setNetwork] = useState('')
  const [chunkSize, setChunkSize] = useState(16)
  const [targets, setTargets] = useState('')
  const [maxConcurrent, setMaxConcurrent] = useState(4)
  const [error, setError] = useState('')
  const [rowErrorId, setRowErrorId] = useState('')
  const [rowError, setRowError] = useState('')
  const eligibleNodes = nodes.filter((node) => node.capabilities.includes('net.discovery.scan')).length

  async function submit() {
    setError('')
    try {
      const body: Record<string, unknown> = { mode, network, max_concurrent_chunks: maxConcurrent }
      if (mode === 'parallel') body.chunk_size = chunkSize
      else body.targets = targets.split(/[,\s]+/).map((value) => value.trim()).filter(Boolean)
      await onCreate(body)
      setNetwork(''); setTargets('')
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not start distributed scan') }
  }

  return <section className="catalog-layout">
    <div className="panel create-card">
      <span className="kicker">ADAPTIVE SCHEDULING</span><h2>Distributed scan</h2>
      <p>{mode === 'parallel'
        ? 'Splits a network into chunks dispatched across whichever capable nodes have capacity, with automatic failover.'
        : 'Checks the same target(s) against every currently capable node and reconciles agreement.'}</p>
      <small>{eligibleNodes} live node{eligibleNodes === 1 ? '' : 's'} currently advertise net.discovery.scan.</small>
      <div className="segmented"><button className={mode === 'parallel' ? 'active' : ''} onClick={() => setMode('parallel')}>PARALLEL</button><button className={mode === 'consensus' ? 'active' : ''} onClick={() => setMode('consensus')}>CONSENSUS</button></div>
      <label className="field"><span>NETWORK / CIDR</span><input value={network} onChange={(event) => setNetwork(event.target.value)} placeholder="192.168.8.0/24" /></label>
      {mode === 'parallel'
        ? <label className="field"><span>CHUNK SIZE (HOSTS)</span><input type="number" min={1} max={256} value={chunkSize} onChange={(event) => setChunkSize(Number(event.target.value))} /></label>
        : <label className="field"><span>TARGETS</span><input value={targets} onChange={(event) => setTargets(event.target.value)} placeholder="192.168.8.9, 192.168.8.10" /></label>}
      <label className="field"><span>MAX CONCURRENT CHUNKS</span><input type="number" min={1} max={32} value={maxConcurrent} onChange={(event) => setMaxConcurrent(Number(event.target.value))} /></label>
      {error && <div className="inspection-error">{error}</div>}
      <button className="primary-action" disabled={!network.trim() || (mode === 'consensus' && !targets.trim())} onClick={submit}>START SCAN</button>
    </div>
    <RecordGrid empty="No distributed scans yet.">{scans.slice().sort((a, b) => b.created_at_ms - a.created_at_ms).map((scan) => {
      const complete = scan.chunks.filter((chunk) => chunk.status === 'complete').length
      const failed = scan.chunks.filter((chunk) => chunk.status === 'failed').length
      const active = scan.status === 'running'
      return <article className="record-card automation-card" key={scan.id}>
        <span className={`record-icon ${active ? 'live' : ''}`}>⬡</span>
        <div>
          <span className="kicker">{scan.mode.toUpperCase()} · {scan.network}</span>
          <h3>{scan.id}</h3>
          <p>{complete}/{scan.chunks.length} chunk{scan.chunks.length === 1 ? '' : 's'} complete{failed ? ` · ${failed} failed` : ''} · status {scan.status}</p>
          {scan.mode === 'consensus' && scan.consensus && <ul className="consensus-summary">
            {Object.entries(scan.consensus.targets).map(([target, info]) => <li key={target} className={`concord-${info.concord}`}>{target}: {info.detected_count}/{info.total_observations} detected ({info.concord})</li>)}
          </ul>}
          {rowErrorId === scan.id && <small className="inspection-error">{rowError}</small>}
        </div>
        <div className="rule-actions">
          {active && <button className="danger" onClick={async () => { setRowErrorId(''); try { await onCancel(scan.id) } catch (err) { setRowErrorId(scan.id); setRowError(err instanceof Error ? err.message : 'Cancel failed') } }}>STOP</button>}
        </div>
      </article>
    })}</RecordGrid>
  </section>
}

function OperatorsView({ operators, approvals, currentOperator, onCreateOperator, onDecideApproval }: {
  operators: PublicOperator[]; approvals: Approval[]; currentOperator: PublicOperator | null
  onCreateOperator: (body: Record<string, unknown>) => Promise<void>
  onDecideApproval: (id: string, decision: 'approved' | 'rejected') => Promise<void>
}) {
  const isAdmin = currentOperator?.role === 'admin'
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<OperatorRole>('operator')
  const [error, setError] = useState('')
  const [rowErrorId, setRowErrorId] = useState('')
  const [rowError, setRowError] = useState('')

  async function submit() {
    setError('')
    try {
      await onCreateOperator({ username: username.trim(), display_name: displayName.trim() || username.trim(), password, role })
      setUsername(''); setDisplayName(''); setPassword('')
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not create operator') }
  }

  async function decide(id: string, decision: 'approved' | 'rejected') {
    setRowErrorId('')
    try { await onDecideApproval(id, decision) }
    catch (err) { setRowErrorId(id); setRowError(err instanceof Error ? err.message : 'Decision failed') }
  }

  const approvalsByRecency = approvals.slice().sort((a, b) => (a.status === 'pending' ? -1 : b.status === 'pending' ? 1 : 0) || b.created_at_ms - a.created_at_ms)

  return <section className="catalog-layout operators-layout">
    <div className="operators-top">
      <div className="panel create-card">
        <span className="kicker">ACCESS CONTROL</span><h2>Operators</h2>
        {!currentOperator && <p>This desktop is in single-operator mode. Creating the first account here switches on real logins, roles, and two-person approval.</p>}
        {currentOperator && !isAdmin && <p>Only an admin operator may create new accounts.</p>}
        {(isAdmin || !currentOperator) && <>
          <p>The first operator created always becomes admin, regardless of the role chosen here.</p>
          <label className="field"><span>USERNAME</span><input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="jsmith" /></label>
          <label className="field"><span>DISPLAY NAME</span><input value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="J. Smith" /></label>
          <label className="field"><span>PASSWORD</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="At least 10 characters" /></label>
          <label className="field"><span>ROLE</span><select value={role} onChange={(event) => setRole(event.target.value as OperatorRole)}>
            <option value="operator">Operator</option><option value="admin">Admin</option><option value="viewer">Viewer</option>
          </select></label>
          {error && <div className="inspection-error">{error}</div>}
          <button className="primary-action" disabled={!username.trim() || password.length < 10} onClick={submit}>+ CREATE OPERATOR</button>
        </>}
      </div>
      <div className="panel">
        <div className="panel-head"><div><span className="kicker">ROSTER</span><h2>{operators.length} operator{operators.length === 1 ? '' : 's'}</h2></div></div>
        <RecordGrid empty="No operators registered yet -- this desktop is in single-operator mode.">{operators.map((item) => <article className="record-card" key={item.id}>
          <span className="record-icon">☺</span>
          <div><span className="kicker">{item.disabled ? 'DISABLED' : 'ACTIVE'}</span><h3>{item.display_name}</h3><p>@{item.username}</p><span className={`role-badge ${item.role}`}>{item.role}</span></div>
        </article>)}</RecordGrid>
      </div>
    </div>
    <div className="panel">
      <div className="panel-head"><div><span className="kicker">MAKER-CHECKER</span><h2>Approvals</h2></div></div>
      <RecordGrid empty="No approval requests yet.">{approvalsByRecency.map((item) => {
        const decidable = isAdmin && item.status === 'pending' && item.requested_by !== currentOperator?.id
        return <article className="record-card automation-card" key={item.id}>
          <span className={`record-icon ${item.status === 'pending' ? 'live' : ''}`}>{item.status === 'approved' ? '✓' : item.status === 'rejected' ? '✕' : item.status === 'failed' ? '!' : '…'}</span>
          <div>
            <span className="kicker">{item.action_type} · {item.status.toUpperCase()}</span>
            <h3>Requested by {item.requested_by_username}</h3>
            <pre className="approval-payload">{JSON.stringify(item.payload, null, 2)}</pre>
            {item.decided_by_username && <small>Decided by {item.decided_by_username}</small>}
            {item.error && <small className="inspection-error">{item.error}</small>}
            {rowErrorId === item.id && <small className="inspection-error">{rowError}</small>}
          </div>
          {decidable && <div className="rule-actions">
            <button onClick={() => decide(item.id, 'approved')}>APPROVE</button>
            <button className="danger" onClick={() => decide(item.id, 'rejected')}>REJECT</button>
          </div>}
        </article>
      })}</RecordGrid>
    </div>
  </section>
}

function FleetView({ nodes, releases, rollouts, onCreateRelease, onCreateRollout, onAdvanceRollout, onRollbackRollout }: { nodes: FleetNode[]; releases: OtaRelease[]; rollouts: OtaRollout[]; onCreateRelease: (body: Record<string, unknown>) => Promise<void>; onCreateRollout: (body: Record<string, unknown>) => Promise<void>; onAdvanceRollout: (id: string) => Promise<void>; onRollbackRollout: (id: string) => Promise<void> }) {
  const [deviceType, setDeviceType] = useState('')
  const [version, setVersion] = useState('')
  const [artifactSha, setArtifactSha] = useState('')
  const [artifactBase64, setArtifactBase64] = useState('')
  const [artifactFileName, setArtifactFileName] = useState('')
  const [releaseError, setReleaseError] = useState('')
  const [selectedRelease, setSelectedRelease] = useState('')
  const [batchSize, setBatchSize] = useState(2)
  const [rolloutError, setRolloutError] = useState('')
  const [rowErrorId, setRowErrorId] = useState('')
  const [rowError, setRowError] = useState('')
  return <section className="catalog-layout fleet-layout">
    <div className="panel create-card fleet-inventory">
      <span className="kicker">DEVICE INVENTORY</span><h2>Fleet nodes</h2>
      <p>Live health, firmware, and desired-config drift across every node this coordinator has seen.</p>
      <RecordGrid empty="No fleet nodes observed yet.">{nodes.map((node) => <article className="record-card" key={node.device_id}><span className={`record-icon ${node.status === 'ready' ? 'live' : ''}`}>▤</span><div><span className="kicker">{node.device_type.toUpperCase()} · {node.status}</span><h3>{node.device_id}</h3><p>{node.firmware || 'unknown firmware'} · {node.address}</p><small>{Object.keys(node.drift).length ? `Drift: ${Object.keys(node.drift).join(', ')}` : 'In sync with desired config'} · last seen {stamp(node.last_seen_ms)}</small></div></article>)}</RecordGrid>
    </div>
    <div className="fleet-actions">
    <div className="panel create-card">
      <span className="kicker">SIGNED RELEASE</span><h2>Publish OTA artifact</h2>
      <label className="field"><span>DEVICE TYPE</span><input value={deviceType} onChange={(event) => setDeviceType(event.target.value)} placeholder="poe-p4" /></label>
      <label className="field"><span>VERSION</span><input value={version} onChange={(event) => setVersion(event.target.value)} placeholder="0.2.0" /></label>
      <label className="field"><span>FIRMWARE ARTIFACT</span><input type="file" onChange={async (event) => {
        setReleaseError(''); setArtifactSha(''); setArtifactBase64(''); setArtifactFileName('')
        const file = event.target.files?.[0]
        if (!file) return
        try {
          const { base64, sha256 } = await readArtifactFile(file)
          setArtifactBase64(base64); setArtifactSha(sha256); setArtifactFileName(file.name)
        } catch { setReleaseError('Could not read the selected firmware file') }
      }} /></label>
      {artifactFileName && <p>{artifactFileName} · sha256 {artifactSha.slice(0, 16)}…</p>}
      {releaseError && <div className="inspection-error">{releaseError}</div>}
      <button className="primary-action" disabled={!deviceType.trim() || !version.trim() || !artifactBase64} onClick={async () => { setReleaseError(''); try { await onCreateRelease({ device_type: deviceType.trim(), version: version.trim(), artifact_sha256: artifactSha, artifact_base64: artifactBase64 }); setVersion(''); setArtifactSha(''); setArtifactBase64(''); setArtifactFileName('') } catch (error) { setReleaseError(error instanceof Error ? error.message : 'Could not sign release') } }}>SIGN RELEASE</button>
      <RecordGrid empty="No releases signed yet.">{releases.map((release) => <article className={`record-card ${selectedRelease === release.id ? 'selected-record' : ''}`} key={release.id}><span className="record-icon">✎</span><div><span className="kicker">{release.device_type.toUpperCase()}</span><h3>{release.version}</h3><p>{release.artifact_sha256.slice(0, 16)}…</p><small>Signed {stamp(release.created_at_ms)}</small></div><div className="rule-actions"><button onClick={() => setSelectedRelease(release.id)}>{selectedRelease === release.id ? 'SELECTED' : 'SELECT FOR ROLLOUT'}</button></div></article>)}</RecordGrid>
    </div>
    <div className="panel create-card">
      <span className="kicker">STAGED ROLLOUT</span><h2>Deploy in batches</h2>
      <p>{selectedRelease ? `Targeting release ${selectedRelease}` : 'Select a signed release above first.'}</p>
      <label className="field"><span>BATCH SIZE</span><input type="number" min={1} max={16} value={batchSize} onChange={(event) => setBatchSize(Number(event.target.value))} /></label>
      {rolloutError && <div className="inspection-error">{rolloutError}</div>}
      <button className="primary-action" disabled={!selectedRelease} onClick={async () => { setRolloutError(''); try { await onCreateRollout({ release_id: selectedRelease, batch_size: batchSize }) } catch (error) { setRolloutError(error instanceof Error ? error.message : 'Could not create rollout') } }}>CREATE ROLLOUT</button>
      <RecordGrid empty="No rollouts staged yet.">{rollouts.map((rollout) => { const verified = rollout.targets.filter((item) => item.status === 'verified').length; const attempted = rollout.targets.filter((item) => item.status !== 'pending').length; const canAdvance = rollout.targets.some((item) => item.status === 'pending'); const canRollback = (rollout.status === 'rollback_required' || rollout.status === 'partial') && Boolean(rollout.previous_release_id); return <article className="record-card" key={rollout.id}><span className={`record-icon ${rollout.status === 'running' ? 'live' : ''}`}>⇪</span><div><span className="kicker">{rollout.status.replace(/_/g, ' ').toUpperCase()}</span><h3>{rollout.release_id}</h3><p>{attempted}/{rollout.targets.length} attempted · {verified} verified</p>{rowErrorId === rollout.id && <small className="inspection-error">{rowError}</small>}<small>Updated {stamp(rollout.updated_at_ms)}</small></div><div className="rule-actions">{canAdvance && <button onClick={async () => { setRowErrorId(''); try { await onAdvanceRollout(rollout.id) } catch (err) { setRowErrorId(rollout.id); setRowError(err instanceof Error ? err.message : 'Advance failed') } }}>ADVANCE</button>}{canRollback && <button className="danger" onClick={async () => { setRowErrorId(''); try { await onRollbackRollout(rollout.id) } catch (err) { setRowErrorId(rollout.id); setRowError(err instanceof Error ? err.message : 'Rollback failed') } }}>ROLLBACK</button>}</div></article> })}</RecordGrid>
    </div>
    </div>
  </section>
}

type MapPoint = { id: string; address: string; label: string; sub: string; live: boolean; node?: ReconNode }

function NetworkGraph({ points, selected, onSelect }: { points: MapPoint[]; selected: string[]; onSelect: (host: string) => void }) {
  const visible = points.slice(0, 18)
  const radius = 36
  return <section className="network-graph panel"><svg viewBox="0 0 100 70" role="img" aria-label="Interactive project node graph"><defs><filter id="glow"><feGaussianBlur stdDeviation=".7" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>{visible.map((point, index) => { const angle = index / Math.max(visible.length, 1) * Math.PI * 2 - Math.PI / 2; const x = 50 + Math.cos(angle) * radius; const y = 35 + Math.sin(angle) * 25; const chosen = selected.includes(point.address); return <g className={`graph-node ${chosen ? 'selected' : ''}`} key={point.id} role="button" tabIndex={0} aria-pressed={chosen} onClick={() => onSelect(point.address)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(point.address) } }}><line x1="50" y1="35" x2={x} y2={y} /><circle className={point.live ? 'live' : ''} cx={x} cy={y} r={chosen ? '3' : '2.2'}/><text x={x} y={y + 5}>{point.label}</text><text className="sub" x={x} y={y + 7.8}>{point.sub}</text></g>})}<circle className="hub" cx="50" cy="35" r="3.2"/><text className="hub-label" x="50" y="42">PROJECT</text></svg>{!visible.length && <div className="graph-empty">Run a project Scout operation to populate this map.</div>}</section>
}

function HostInspector({ host, selected, evidence, project, ports, setPorts, authorised, setAuthorised, busy, error, onRun }: { host?: MapPoint; selected: string[]; evidence: EvidenceRecord[]; project?: Project; ports: string; setPorts: (value: string) => void; authorised: boolean; setAuthorised: (value: boolean) => void; busy: boolean; error: string; onRun: () => Promise<void> }) {
  const latest = evidence.find((item) => item.kind === 'tcp-services')
  const observation = latest?.data?.hosts?.find((item) => (typeof item === 'string' ? item : item.address) === host?.address)
  const openPorts = typeof observation === 'object' ? observation.open_ports ?? [] : []
  const parsedPorts = ports.split(/[\s,]+/).filter(Boolean).map(Number)
  const validPorts = parsedPorts.length > 0 && parsedPorts.length <= 128 && parsedPorts.every((port) => Number.isInteger(port) && port > 0 && port <= 65535)
  return <aside className="host-inspector panel">
    <div className="inspector-head"><div><span className="kicker">TARGET INSPECTOR</span><h2>{host?.address ?? (selected.length ? `${selected.length} hosts selected` : 'Select a host')}</h2></div><span className="count">{selected.length}</span></div>
    {host ? <><div className="host-state"><span className={`record-icon ${host.live ? 'live' : ''}`}>⌁</span><div><strong>{host.label}</strong><small>{host.live ? 'Active Reconclave node' : 'Previously observed host'}</small></div></div><div className="inspector-facts"><span>ADDRESS<strong>{host.address}</strong></span><span>STATUS<strong>{host.node?.status ?? (host.live ? 'online' : 'not currently advertised')}</strong></span><span>IDENTITY<strong>{host.node?.device_id ?? 'Unidentified'}</strong></span><span>ROLES<strong>{host.node?.roles.join(', ') || 'Observed endpoint'}</strong></span><span>FIRMWARE<strong>{host.node?.firmware ?? 'Unknown'}</strong></span><span>EVIDENCE<strong>{evidence.length} record(s)</strong></span></div>{host.node && <div className="host-capabilities"><span>CAPABILITIES</span>{host.node.capabilities.map((capability) => <i key={capability}>{capability}</i>)}</div>}{latest && <div className="last-inspection"><span>LATEST TCP OBSERVATION</span><strong>{openPorts.length ? openPorts.join(', ') : 'No open ports observed'}</strong><small>{stamp(latest.captured_at_ms)}</small></div>}</> : <div className="inspector-empty">Choose one host for its full identity and evidence history, or choose several to inspect them together.</div>}
    <div className="inspection-form"><div className="section-label"><span>TCP PORT INSPECTION</span><small>Up to 16 local hosts / 128 ports</small></div><div className="port-presets"><button onClick={() => setPorts('22, 53, 80, 443, 445, 1883, 8080, 8443')}>COMMON</button><button onClick={() => setPorts('80, 443, 8000, 8080, 8443, 8765, 8767')}>WEB</button><button onClick={() => setPorts('20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5900')}>EXTENDED</button></div><label className="field"><span>PORTS</span><input value={ports} onChange={(event) => setPorts(event.target.value)} aria-invalid={!validPorts} placeholder="22, 80, 443" /></label><label className="authorise compact"><input type="checkbox" checked={authorised} onChange={(event) => setAuthorised(event.target.checked)} /><span><strong>AUTHORISE TARGETED INSPECTION</strong><small>I am authorised to assess the selected local hosts.</small></span></label>{!project && <div className="inspection-error">Select a project above so the inspection and evidence have a case record.</div>}{error && <div className="inspection-error">{error}</div>}<button className="primary-action inspect-action" disabled={!project || !selected.length || !authorised || !validPorts || busy} onClick={onRun}>{busy ? 'INSPECTING…' : `INSPECT ${selected.length || ''} HOST${selected.length === 1 ? '' : 'S'}`}</button></div>
  </aside>
}
