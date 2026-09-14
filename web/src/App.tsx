import { useEffect, useMemo, useRef, useState } from 'react'
import type { Activity, AppState, CapabilityDescriptor, FindingStatus, Project, ReconNode, ScanJob, SessionInfo, WorkspaceData } from './types'
import WorkspaceViews from './WorkspaceViews'
import LoginScreen from './LoginScreen'

const emptyState: AppState = { revision: 0, nodes: [], coordinator_id: '', updated_at_ms: 0 }
const emptyWorkspace: WorkspaceData = { revision: 0, projects: [], jobs: [], evidence: [], automations: [], workflows: [], workflow_runs: [], scopes: [], audit_events: [], findings: [], fleet_nodes: [], fleet_configs: [], ota_releases: [], ota_rollouts: [], distributed_scans: [], operators: [], approvals: [] }

// A Bearer token in localStorage, not a cookie -- a cookie is attached to every request
// automatically regardless of origin, which is exactly the ambient-credential problem
// trusted_api_origin (desktop_app.py) already exists to guard against for this loopback
// API. A token only travels if this code attaches it, so adding sessions doesn't widen
// cross-origin/CSRF exposure at all.
const TOKEN_STORAGE_KEY = 'reconclave.session_token'
function getToken(): string { try { return localStorage.getItem(TOKEN_STORAGE_KEY) ?? '' } catch { return '' } }
function setToken(token: string) { try { localStorage.setItem(TOKEN_STORAGE_KEY, token) } catch { /* private-browsing etc -- session just won't survive a reload */ } }
function clearToken() { try { localStorage.removeItem(TOKEN_STORAGE_KEY) } catch { /* see above */ } }
function authHeaders(): Record<string, string> {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

const ACTIVITY_LIMIT = 20

function savedActivity(): Activity[] {
  try {
    const value = JSON.parse(localStorage.getItem('reconclave.activity') ?? '[]') as Array<Omit<Activity, 'time'> & { time: string }>
    return value.slice(0, ACTIVITY_LIMIT).map((item) => ({ ...item, time: new Date(item.time) }))
  } catch { return [] }
}

// Human label for a job's capability, for notification titles ("Scout scan
// started" reads better than "net.discovery.scan started").
function jobLabel(capability?: string) {
  if (!capability) return 'Job'
  if (capability === 'net.discovery.scan') return 'Scout scan'
  if (capability === 'net.tcp.inspect') return 'TCP inspection'
  if (capability.startsWith('tool.')) return capability.slice(5).replace(/\./g, ' ')
  return capability
}

function savedJob(): ScanJob | null {
  try { return JSON.parse(localStorage.getItem('reconclave.scoutJob') ?? 'null') as ScanJob | null }
  catch { return null }
}

function timeAgo(seconds: number) {
  if (seconds < 2) return 'just now'
  if (seconds < 60) return `${Math.floor(seconds)}s ago`
  return `${Math.floor(seconds / 60)}m ago`
}

function bytes(value?: number) {
  if (!value) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let amount = value
  let unit = 0
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1 }
  return `${amount.toFixed(unit > 2 ? 1 : 0)} ${units[unit]}`
}

function capabilityMeta(node: ReconNode, id: string): CapabilityDescriptor {
  return node.capability_descriptors.find((item) => item.id === id) ?? {
    id, version: 1, permission: 'public', features: [], limits: { weight: 1, max_concurrency: 1 },
  }
}

function NodeGlyph({ node }: { node: ReconNode }) {
  const label = node.device_type.includes('desktop') ? 'DX' :
    node.device_type.includes('p4') ? 'P4' : node.device_type.includes('card') ? 'CP' : 'NX'
  return <div className={`node-glyph ${node.status}`}><span>{label}</span><i /></div>
}

function defaultScope(address: string) {
  const octets = address.split('.')
  if (octets.length !== 4 || octets.some((part) => !/^\d+$/.test(part))) {
    return { network: '', start: '', end: '' }
  }
  const prefix = octets.slice(0, 3).join('.')
  return { network: `${prefix}.0/24`, start: `${prefix}.1`, end: `${prefix}.254` }
}

function App() {
  const [view, setView] = useState<'network' | 'map' | 'jobs' | 'projects' | 'evidence' | 'automations' | 'workflows' | 'scopes' | 'findings' | 'timeline' | 'fleet' | 'distributed' | 'operators'>('network')
  const [state, setState] = useState<AppState>(emptyState)
  const [workspace, setWorkspace] = useState<WorkspaceData>(emptyWorkspace)
  const [projectId, setProjectId] = useState(() => localStorage.getItem('reconclave.project') ?? '')
  const [selectedId, setSelectedId] = useState('')
  const [connected, setConnected] = useState(false)
  const [busyCapability, setBusyCapability] = useState('')
  const [result, setResult] = useState<Record<string, unknown> | null>(null)
  const [activity, setActivity] = useState<Activity[]>(savedActivity)
  const [unreadCount, setUnreadCount] = useState(0)
  const [notifOpen, setNotifOpen] = useState(false)
  const notifRef = useRef<HTMLDivElement>(null)
  const seenAuditIds = useRef<Set<string> | null>(null)
  const lastJobStatus = useRef<Map<string, string>>(new Map())
  const [filter, setFilter] = useState('')
  const [scoutOpen, setScoutOpen] = useState(false)
  const [scope, setScope] = useState({ network: '', start: '', end: '' })
  const [authorised, setAuthorised] = useState(false)
  const [scoutError, setScoutError] = useState('')
  const [recurringMinutes, setRecurringMinutes] = useState(0)
  const [scanJob, setScanJob] = useState<ScanJob | null>(savedJob)
  const [session, setSession] = useState<SessionInfo | null>(null)
  // null while /api/session hasn't answered yet; once it has, data-loading only starts
  // once we know either no login is required at all (legacy single-operator mode) or
  // login has actually happened -- see the session-fetch effect and the gated
  // data-loading effect right after it.
  const readyToLoadData = session !== null && (!session.auth_required || session.operator !== null)
  const statusFailures = useRef(0)

  useEffect(() => {
    fetch('/api/session', { headers: authHeaders() }).then((response) => response.json()).then(setSession)
      .catch(() => setSession({ auth_required: false, operator: null }))
  }, [])

  useEffect(() => {
    if (!readyToLoadData) return
    fetch('/api/state', { headers: authHeaders() }).then((response) => response.json()).then(setState).catch(() => setConnected(false))
    refreshWorkspace()
    // Workspace mutations also happen in the background when autonomous nodes
    // upload their durable outboxes. Node-state SSE revisions do not cover
    // those writes, so keep the project/evidence view live independently.
    const workspaceTimer = window.setInterval(refreshWorkspace, 2000)
    // EventSource can't send custom headers, so the Bearer token travels as a query
    // param here specifically -- the one exception to "auth always travels in a
    // header", accepted only because this is a loopback-only, single-workstation tool.
    const streamToken = getToken()
    const events = new EventSource(streamToken ? `/api/events?token=${encodeURIComponent(streamToken)}` : '/api/events')
    events.addEventListener('state', (event) => {
      setState(JSON.parse((event as MessageEvent).data))
      setConnected(true)
    })
    events.onopen = () => setConnected(true)
    events.onerror = () => setConnected(false)
    return () => { events.close(); window.clearInterval(workspaceTimer) }
  }, [readyToLoadData])

  useEffect(() => { localStorage.setItem('reconclave.project', projectId) }, [projectId])

  // The Network view's own Scout dispatch/poll flow below already posts its
  // own richer notifications ("Scout dispatched", "Scout complete" with a
  // host count) for jobs it started - and those same status changes also
  // land in job.updated audit events. Call this wherever that flow already
  // notifies, so the generic audit-derived detector below recognises the
  // status as already surfaced and doesn't post a second, blander duplicate.
  function markJobNotified(jobId: string | undefined, status: string | undefined) {
    if (jobId && status) lastJobStatus.current.set(jobId, status)
  }

  // Derives notifications from the server's own audit trail rather than only
  // from actions the browser itself initiated - this is what actually covers
  // background/autonomous events (an automation rule firing at 3am, a
  // recurring scan completing while the operator is on a different tab) that
  // have no client-side call site to hook. audit_events arrives via the same
  // 2s workspace poll every view already depends on, so this runs regardless
  // of which page is open.
  useEffect(() => {
    const seen = seenAuditIds.current
    const firstLoad = seen === null
    const nextSeen = seen ?? new Set<string>()
    for (const event of workspace.audit_events) {
      if (nextSeen.has(event.id)) continue
      nextSeen.add(event.id)
      if (firstLoad) continue // don't replay pre-existing history as new notifications
      if (event.action === 'automation.triggered') {
        const context = [event.node_id, event.condition].filter(Boolean).join(' · ')
        addActivity({ title: 'Rule triggered', detail: `${context ? context + ' → ' : ''}${event.outcome}`, tone: 'info' })
      } else if (event.action === 'job.updated') {
        // upsert_job audits on every poll tick, not just on a real status
        // change - only notify when this job's status actually moved, or a
        // still-"running" scan would spam a notification every couple seconds.
        if (lastJobStatus.current.get(event.subject_id) === event.outcome) continue
        lastJobStatus.current.set(event.subject_id, event.outcome)
        const job = workspace.jobs.find((item) => item.id === event.subject_id)
        const label = jobLabel(job?.capability)
        const detail = job?.provider_id ?? event.subject_id
        if (event.outcome === 'running' || event.outcome === 'waiting') {
          addActivity({ title: `${label} started`, detail, tone: 'info' })
        } else if (event.outcome === 'complete') {
          addActivity({ title: `${label} complete`, detail: job?.hosts?.length ? `${job.hosts.length} host${job.hosts.length === 1 ? '' : 's'} · ${detail}` : detail, tone: 'ok' })
        } else if (event.outcome === 'failed') {
          addActivity({ title: `${label} failed`, detail: job?.error || detail, tone: 'warn' })
        } else if (event.outcome === 'cancelled') {
          addActivity({ title: `${label} cancelled`, detail, tone: 'info' })
        }
      } else if (event.action === 'evidence.captured') {
        // A rule pushed to a capable device (device_managed: true) is
        // evaluated and fired entirely on-device - the desktop never calls
        // its own trigger path, so "automation.triggered" above never fires
        // for it. The desktop only learns about it once outbox sync pulls
        // the resulting evidence back, tagged with the rule that produced
        // it; that is this platform's only signal that an autonomous rule
        // fired, so notify from it directly rather than missing the event.
        const record = workspace.evidence.find((item) => item.id === event.subject_id)
        const ruleId = record?.data?.rule_id
        if (typeof ruleId === 'string' && ruleId) {
          addActivity({ title: 'Rule fired', detail: record?.summary || ruleId, tone: 'ok' })
        }
      }
    }
    seenAuditIds.current = nextSeen
  }, [workspace.audit_events, workspace.jobs])

  useEffect(() => {
    if (!notifOpen) return
    function onOutsideClick(event: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) setNotifOpen(false)
    }
    document.addEventListener('mousedown', onOutsideClick)
    return () => document.removeEventListener('mousedown', onOutsideClick)
  }, [notifOpen])

  async function refreshWorkspace() {
    const response = await fetch('/api/workspace', { headers: authHeaders() })
    if (response.ok) setWorkspace(await response.json())
    else if (response.status === 401) signOut()
  }

  async function postWorkspace(path: string, body: Record<string, unknown>) {
    const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify(body) })
    if (!response.ok) { const error = await response.json(); throw new Error(error.message ?? error.error ?? 'Workspace update failed') }
    const result = await response.json()
    await refreshWorkspace()
    return result
  }

  function signOut() {
    clearToken()
    setSession((current) => current ? { ...current, operator: null } : { auth_required: true, operator: null })
  }

  async function login(username: string, password: string) {
    const response = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) })
    const result = await response.json()
    if (!response.ok) throw new Error(result.message ?? result.error ?? 'Login failed')
    setToken(result.token)
    setSession({ auth_required: true, operator: result.operator })
  }

  async function logout() {
    try { await fetch('/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: '{}' }) }
    finally { signOut() }
  }

  async function createOperator(body: Record<string, unknown>) {
    await postWorkspace('/api/operators', body)
    addActivity({ title: 'Operator created', detail: String(body.username ?? ''), tone: 'info' })
  }

  async function decideApproval(id: string, decision: 'approved' | 'rejected') {
    await postWorkspace(`/api/approvals/${encodeURIComponent(id)}/decide`, { decision })
    addActivity({ title: decision === 'approved' ? 'Approval granted' : 'Approval rejected', detail: id, tone: decision === 'approved' ? 'ok' : 'warn' })
  }

  async function createProject(name: string, description: string) {
    const project = await postWorkspace('/api/projects', { name, description }) as Project
    setProjectId(project.id)
  }

  async function inspectSelectedHosts(hosts: string[], ports: number[]) {
    const scopeId = workspace.scopes.filter((item) => item.project_id === projectId && item.expires_at_ms > Date.now()).sort((a, b) => b.revision - a.revision)[0]?.id
    const response = await fetch('/api/inspect', { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify({ hosts, ports, project_id: projectId, scope_id: scopeId, operator_authorised: true }) })
    const result = await response.json()
    if (!response.ok) throw new Error(result.message ?? result.error ?? 'Host inspection failed')
    await refreshWorkspace()
    markJobNotified(result.job_id, 'complete')
    addActivity({ title: 'TCP inspection complete', detail: `${hosts.length} host${hosts.length === 1 ? '' : 's'} · ${ports.length} ports`, tone: 'ok' })
    return result
  }

  async function createAutomation(body: Record<string, unknown>) {
    const scopeId = workspace.scopes.filter((item) => item.project_id === projectId && item.expires_at_ms > Date.now()).sort((a, b) => b.revision - a.revision)[0]?.id
    await postWorkspace('/api/automations', { ...body, project_id: projectId, scope_id: scopeId, operator_authorised: true })
    addActivity({ title: 'Automation armed', detail: `${body.condition} → ${body.playbook}`, tone: 'info' })
  }

  async function updateAutomation(id: string, body: Record<string, unknown>) {
    await postWorkspace(`/api/automations/${encodeURIComponent(id)}`, body)
  }

  async function deleteAutomation(id: string) {
    const response = await fetch(`/api/automations/${encodeURIComponent(id)}`, { method: 'DELETE', headers: authHeaders() })
    if (!response.ok) throw new Error('Could not delete automation')
    await refreshWorkspace()
  }

  async function createWorkflow(body: Record<string, unknown>) {
    await postWorkspace('/api/workflows', { ...body, project_id: projectId })
    addActivity({ title: 'Workflow created', detail: String(body.name ?? 'Workflow'), tone: 'info' })
  }

  async function runWorkflow(id: string) {
    const scopeId = workspace.scopes.filter((item) => item.project_id === projectId && item.expires_at_ms > Date.now()).sort((a, b) => b.revision - a.revision)[0]?.id
    await postWorkspace(`/api/workflows/${encodeURIComponent(id)}/runs`, { scope_id: scopeId })
    addActivity({ title: 'Workflow queued', detail: id, tone: 'info' })
  }

  async function cancelWorkflow(id: string) {
    await postWorkspace(`/api/workflow-runs/${encodeURIComponent(id)}/cancel`, {})
  }

  async function updateWorkflow(id: string, body: Record<string, unknown>) {
    await postWorkspace(`/api/workflows/${encodeURIComponent(id)}`, body)
    addActivity({ title: 'Workflow updated', detail: id, tone: 'info' })
  }

  async function deleteWorkflow(id: string) {
    const response = await fetch(`/api/workflows/${encodeURIComponent(id)}`, { method: 'DELETE', headers: authHeaders() })
    if (!response.ok) throw new Error('Could not delete workflow (an active run may still be in progress)')
    await refreshWorkspace()
  }

  // Once operators exist, a non-admin operator's request for one of the two
  // approval-registry actions (scope.create, fleet.release.create) is transparently
  // rerouted to POST /api/approvals instead of executing directly -- the same form,
  // the same button, but the desktop_app.py route itself would reject a direct
  // non-admin call outright once any operator exists (see require_admin_when_multi_
  // operator), so this is what actually lets a non-admin operator use these forms at
  // all rather than just hitting a 403.
  async function submitOrRequestApproval(actionType: string, path: string, payload: Record<string, unknown>): Promise<boolean> {
    const role = session?.operator?.role
    if (session?.auth_required && role && role !== 'admin') {
      await postWorkspace('/api/approvals', { action_type: actionType, payload })
      return true
    }
    await postWorkspace(path, payload)
    return false
  }

  async function createScope(body: Record<string, unknown>) {
    const requested = await submitOrRequestApproval('scope.create', '/api/scopes',
      { ...body, project_id: projectId, operator_authorised: true })
    addActivity(requested
      ? { title: 'Scope approval requested', detail: String(body.included_networks), tone: 'info' }
      : { title: 'Scope approved', detail: String(body.included_networks), tone: 'ok' })
  }

  async function importFindings(body: Record<string, unknown>) {
    await postWorkspace('/api/findings/import', { ...body, project_id: projectId, operator_authorised: true })
    addActivity({ title: 'Vulnerability data imported', detail: String(body.format), tone: 'info' })
  }

  async function correlateFindings() {
    const result = await postWorkspace('/api/findings/correlate', { project_id: projectId }) as
      { confirmed_count: number; new_candidate_count: number }
    addActivity({ title: 'Correlation complete', detail: `${result.confirmed_count} confirmed · ${result.new_candidate_count} new candidate(s)`, tone: 'info' })
    return result
  }

  async function setFindingStatus(id: string, status: FindingStatus) {
    await postWorkspace(`/api/findings/${encodeURIComponent(id)}/status`, { status })
    addActivity({ title: 'Finding status updated', detail: `${id} → ${status}`, tone: 'info' })
  }

  async function setFindingSuppression(id: string, suppressed: boolean, reason: string) {
    await postWorkspace(`/api/findings/${encodeURIComponent(id)}/suppress`, { suppressed, reason })
    addActivity({ title: suppressed ? 'Finding suppressed' : 'Finding unsuppressed', detail: id, tone: 'info' })
  }

  async function createRelease(body: Record<string, unknown>) {
    const requested = await submitOrRequestApproval('fleet.release.create', '/api/fleet/releases',
      { ...body, operator_authorised: true })
    addActivity(requested
      ? { title: 'OTA release approval requested', detail: `${body.device_type} ${body.version}`, tone: 'info' }
      : { title: 'OTA release signed', detail: `${body.device_type} ${body.version}`, tone: 'info' })
  }

  async function createRollout(body: Record<string, unknown>) {
    await postWorkspace('/api/fleet/rollouts', { ...body, operator_authorised: true })
    addActivity({ title: 'Rollout staged', detail: String(body.release_id), tone: 'info' })
  }

  async function advanceRollout(id: string) {
    await postWorkspace(`/api/fleet/${encodeURIComponent(id)}/advance`, {})
  }

  async function rollbackRollout(id: string) {
    await postWorkspace(`/api/fleet/${encodeURIComponent(id)}/rollback`, { operator_authorised: true })
    addActivity({ title: 'Rollout rolled back', detail: id, tone: 'warn' })
  }

  async function createDistributedScan(body: Record<string, unknown>) {
    const scopeId = workspace.scopes.filter((item) => item.project_id === projectId && item.expires_at_ms > Date.now()).sort((a, b) => b.revision - a.revision)[0]?.id
    await postWorkspace('/api/distributed-scans', { ...body, project_id: projectId, scope_id: scopeId })
    addActivity({ title: 'Distributed scan started', detail: `${body.mode} · ${body.network}`, tone: 'info' })
  }

  async function cancelDistributedScan(id: string) {
    await postWorkspace(`/api/distributed-scans/${encodeURIComponent(id)}/cancel`, {})
  }

  useEffect(() => {
    localStorage.setItem('reconclave.activity', JSON.stringify(activity))
  }, [activity])

  useEffect(() => {
    if (scanJob) localStorage.setItem('reconclave.scoutJob', JSON.stringify(scanJob))
    else localStorage.removeItem('reconclave.scoutJob')
  }, [scanJob])

  const nodes = useMemo(() => {
    const query = filter.trim().toLowerCase()
    return query ? state.nodes.filter((node) =>
      [node.device_id, node.device_type, ...node.capabilities].some((value) => value.toLowerCase().includes(query))) : state.nodes
  }, [filter, state.nodes])
  const selected = state.nodes.find((node) => node.device_id === selectedId) ?? state.nodes[0]
  const capabilityCount = new Set(state.nodes.flatMap((node) => node.capabilities)).size
  const coordinatorCount = state.nodes.filter((node) => node.roles.includes('coordinator')).length

  function addActivity(entry: Omit<Activity, 'id' | 'time'>) {
    setActivity((items) => [{ ...entry, id: crypto.randomUUID(), time: new Date() }, ...items].slice(0, ACTIVITY_LIMIT))
    setUnreadCount((count) => count + 1)
  }

  async function requestCapability(node: ReconNode, capability: string, arguments_: Record<string, unknown> = {}, operatorAuthorised = false) {
    setBusyCapability(capability)
    try {
      const response = await fetch(`/api/nodes/${encodeURIComponent(node.device_id)}/invoke`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ capability, arguments: arguments_, operator_authorised: operatorAuthorised,
          project_id: projectId, scope_id: workspace.scopes.filter((item) => item.project_id === projectId && item.expires_at_ms > Date.now()).sort((a, b) => b.revision - a.revision)[0]?.id }),
      })
      const body = await response.json()
      if (!response.ok) throw new Error(body.message ?? body.error ?? 'Request failed')
      if (body.payload?.status === 'rejected' || body.payload?.status === 'error') {
        throw new Error(body.payload?.error?.message ?? body.payload?.error?.code ??
          `Node returned ${body.payload.status}`)
      }
      return body
    } catch (error) {
      throw error instanceof Error ? error : new Error('Request failed')
    } finally {
      setBusyCapability('')
    }
  }

  async function invoke(capability: string) {
    if (!selected) return
    setResult(null)
    try {
      const body = await requestCapability(selected, capability)
      setResult(body)
      addActivity({ title: capability, detail: `${selected.device_id} returned ${body.payload?.status ?? 'a response'}`, tone: 'ok' })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Request failed'
      setResult({ error: message })
      addActivity({ title: capability, detail: message, tone: 'warn' })
    }
  }

  function configureScout() {
    if (!selected) return
    setScope(defaultScope(selected.address))
    setAuthorised(false)
    setScoutError('')
    setScoutOpen(true)
  }

  async function startScout() {
    if (!selected) return
    setScoutError('')
    try {
      const arguments_: Record<string, unknown> = { network: scope.network, start_ip: scope.start, end_ip: scope.end }
      if (recurringMinutes > 0) arguments_.schedule = { interval_ms: recurringMinutes * 60000, after_completion: true }
      const body = await requestCapability(selected, 'net.discovery.scan', arguments_, authorised)
      const next = body.payload?.result as Omit<ScanJob, 'providerId'>
      const archived = { providerId: selected.device_id, projectId, archiveId: `${selected.device_id}-${next.job_id}-${Date.now()}`, scope: { ...scope }, ...next }
      setScanJob(archived)
      if (projectId) await postWorkspace('/api/jobs', { id: archived.archiveId, project_id: projectId, provider_id: selected.device_id, capability: 'net.discovery.scan', status: next.job_status, checked: next.checked, total: next.total, hosts: next.hosts, scope })
      markJobNotified(archived.archiveId, next.job_status)
      setScoutOpen(false)
      addActivity({ title: 'Scout dispatched', detail: `${scope.start} → ${scope.end} via ${selected.device_id}`, tone: 'info' })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Dispatch failed'
      setScoutError(message)
      addActivity({ title: 'Scout refused', detail: message, tone: 'warn' })
    }
  }

  useEffect(() => {
    if (!scanJob || scanJob.job_status !== 'running') return
    const provider = state.nodes.find((node) => node.device_id === scanJob.providerId)
    if (!provider) return
    const timer = window.setTimeout(async () => {
      try {
        const body = await requestCapability(provider, 'coordination.job.status')
        const next = { providerId: provider.device_id, ...body.payload?.result } as ScanJob
        next.archiveId = scanJob.archiveId; next.projectId = scanJob.projectId; next.scope = scanJob.scope
        statusFailures.current = 0
        setScanJob(next)
        if (next.archiveId && next.projectId) await postWorkspace('/api/jobs', { id: next.archiveId, project_id: next.projectId, provider_id: next.providerId, capability: 'net.discovery.scan', status: next.job_status, checked: next.checked, total: next.total, hosts: next.hosts, scope: next.scope, error: next.error })
        markJobNotified(next.archiveId, next.job_status)
        if (next.recurring && (next.run_count ?? 0) > (scanJob.run_count ?? 0)) {
          if (next.archiveId && next.projectId) await postWorkspace('/api/evidence', { id: `${next.archiveId}-run-${next.run_count}`, project_id: next.projectId, job_id: next.archiveId, kind: 'network-hosts', title: `Recurring Scout run ${next.run_count}`, summary: `${next.hosts.length} responsive hosts observed by ${next.providerId}`, data: { hosts: next.hosts, scope: next.scope, provider_id: next.providerId, run_count: next.run_count } })
          addActivity({ title: `Scout run ${next.run_count} complete`, detail: `${next.hosts.length} responsive hosts observed`, tone: 'ok' })
        }
        if (next.job_status === 'complete') {
          if (next.archiveId && next.projectId) await postWorkspace('/api/evidence', { id: `${next.archiveId}-network`, project_id: next.projectId, job_id: next.archiveId, kind: 'network-hosts', title: `Scout observation · ${next.scope?.network ?? 'network'}`, summary: `${next.hosts.length} responsive hosts observed by ${next.providerId}`, data: { hosts: next.hosts, scope: next.scope, provider_id: next.providerId } })
          addActivity({ title: 'Scout complete', detail: `${next.hosts.length} responsive host${next.hosts.length === 1 ? '' : 's'} observed`, tone: 'ok' })
        }
      } catch (error) {
        statusFailures.current += 1
        const message = error instanceof Error ? error.message : 'Status request failed'
        if (statusFailures.current >= 3) {
          setScanJob((current) => current ? { ...current, job_status: 'failed', error: message } : current)
          addActivity({ title: 'Scout telemetry lost', detail: message, tone: 'warn' })
        }
      }
    }, 1000)
    return () => window.clearTimeout(timer)
  }, [scanJob, state.nodes])

  async function cancelScout() {
    if (!scanJob) return
    const provider = state.nodes.find((node) => node.device_id === scanJob.providerId)
    if (!provider) return
    try {
      const body = await requestCapability(provider, 'coordination.job.cancel', { job_id: scanJob.job_id })
      setScanJob({ providerId: provider.device_id, ...body.payload?.result })
      addActivity({ title: 'Scout cancelled', detail: provider.device_id, tone: 'info' })
    } catch (error) {
      addActivity({ title: 'Cancel failed', detail: error instanceof Error ? error.message : 'Request failed', tone: 'warn' })
    }
  }

  if (session && session.auth_required && !session.operator) return <LoginScreen onLogin={login} />

  return (
    <div className="app-shell">
      <div className="ambient ambient-one" /><div className="ambient ambient-two" />
      <header className="topbar">
        <div className="brand-mark"><span>R</span></div>
        <div className="brand"><strong>RECONCLAVE</strong><span>OPERATIONS DECK</span></div>
        <div className="topbar-spacer" />
        <div className={`link-state ${connected ? 'online' : ''}`}><i />{connected ? 'LIVE LINK' : 'RECONNECTING'}</div>
        <div className="notif-wrap" ref={notifRef}>
          <button className={`notif-bell ${notifOpen ? 'active' : ''}`} title="Notifications"
            onClick={() => { setNotifOpen((open) => !open); if (!notifOpen) setUnreadCount(0) }}>
            <span>⚑</span>
            {unreadCount > 0 && <i className="notif-badge">{unreadCount > 9 ? '9+' : unreadCount}</i>}
          </button>
          {notifOpen && <div className="notif-dropdown panel">
            <div className="panel-head"><div><span className="kicker">NOTIFICATIONS</span><h2>Recent operations</h2></div><span className="live-tag"><i />LIVE</span></div>
            <div className="timeline">
              {activity.map((item) => <article key={item.id}><i className={item.tone} /><div><strong>{item.title}</strong><p>{item.detail}</p></div><time>{item.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</time></article>)}
              {!activity.length && <div className="empty"><span>∿</span><strong>Channel is quiet</strong><small>Rule triggers, scan lifecycle, and operator actions will appear here.</small></div>}
            </div>
          </div>}
        </div>
        {session?.operator
          ? <div className="operator-chip"><strong>{session.operator.display_name}</strong><span className={`role-badge ${session.operator.role}`}>{session.operator.role}</span><button onClick={logout}>SIGN OUT</button></div>
          : <button className="operator"><span>LOCAL</span><strong>{state.coordinator_id || 'INITIALISING'}</strong></button>}
      </header>

      <aside className="rail">
        <nav aria-label="Primary navigation">
          <button className={view === 'network' ? 'active' : ''} title="Network" onClick={() => setView('network')}><span>⌁</span><small>Network</small></button>
          <button className={view === 'map' ? 'active' : ''} title="Map" onClick={() => setView('map')}><span>◎</span><small>Map</small></button>
          <button className={view === 'jobs' ? 'active' : ''} title="Jobs" onClick={() => setView('jobs')}><span>◫</span><small>Jobs</small></button>
          <button className={view === 'projects' ? 'active' : ''} title="Projects" onClick={() => setView('projects')}><span>◇</span><small>Projects</small></button>
          <button className={view === 'evidence' ? 'active' : ''} title="Evidence" onClick={() => setView('evidence')}><span>▱</span><small>Evidence</small></button>
          <button className={view === 'automations' ? 'active' : ''} title="Automations" onClick={() => setView('automations')}><span>↻</span><small>Rules</small></button>
          <button className={view === 'workflows' ? 'active' : ''} title="Workflows" onClick={() => setView('workflows')}><span>⎇</span><small>Flows</small></button>
          <button className={view === 'scopes' ? 'active' : ''} title="Scopes" onClick={() => setView('scopes')}><span>⌗</span><small>Scope</small></button>
          <button className={view === 'findings' ? 'active' : ''} title="Findings" onClick={() => setView('findings')}><span>△</span><small>Risks</small></button>
          <button className={view === 'timeline' ? 'active' : ''} title="Timeline" onClick={() => setView('timeline')}><span>≋</span><small>Audit</small></button>
          <button className={view === 'fleet' ? 'active' : ''} title="Fleet" onClick={() => setView('fleet')}><span>▤</span><small>Fleet</small></button>
          <button className={view === 'distributed' ? 'active' : ''} title="Distributed scanning" onClick={() => setView('distributed')}><span>⬡</span><small>Distrib</small></button>
          <button className={view === 'operators' ? 'active' : ''} title="Operators and approvals" onClick={() => setView('operators')}><span>☺</span><small>Access</small></button>
        </nav>
        <div className="rail-foot"><div className="pulse-ring" /><small>RC/01</small></div>
      </aside>

      <main>{view === 'network' ? <>
        <section className="hero">
          <div><p className="eyebrow">DISTRIBUTED OPERATIONS</p><h1>Network constellation</h1>
            <p className="subhead">Live capability map across trusted and discoverable nodes.</p></div>
          <div className="hero-time"><span>{state.updated_at_ms ? new Date(state.updated_at_ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--:--'}</span><small>LAST TELEMETRY</small></div>
        </section>

        <section className="metrics">
          <article><span className="metric-icon cyan">⌁</span><div><strong>{state.nodes.length.toString().padStart(2, '0')}</strong><small>ACTIVE NODES</small></div><em>DISCOVERED</em></article>
          <article><span className="metric-icon violet">◇</span><div><strong>{capabilityCount.toString().padStart(2, '0')}</strong><small>CAPABILITIES</small></div><em>AVAILABLE</em></article>
          <article><span className="metric-icon amber">△</span><div><strong>{coordinatorCount.toString().padStart(2, '0')}</strong><small>COORDINATORS</small></div><em>ONLINE</em></article>
        </section>

        {scanJob && <section className={`job-strip ${scanJob.job_status}`}>
          <div className="job-orbit"><span>{scanJob.job_status === 'running' ? '⌁' : '✓'}</span></div>
          <div className="job-title"><span className="kicker">ACTIVE OPERATION</span><strong>NETWORK SCOUT</strong><small>{scanJob.providerId} · job {scanJob.job_id ?? 'pending'}{scanJob.recurring ? ` · run ${scanJob.run_count ?? 0}` : ''}</small></div>
          <div className="job-progress"><div><span style={{ width: `${scanJob.total ? Math.min(100, scanJob.checked / scanJob.total * 100) : 0}%` }} /></div><small>{scanJob.checked} / {scanJob.total} ADDRESSES</small></div>
          <div className="job-hosts"><strong>{scanJob.hosts?.length ?? 0}</strong><small>HOSTS</small></div>
          <span className={`status-pill ${scanJob.job_status}`}><i />{scanJob.job_status}</span>
          {scanJob.error && <small className="job-error">{scanJob.error}</small>}
          {scanJob.job_status === 'running' && state.nodes.find((node) => node.device_id === scanJob.providerId)?.capabilities.includes('coordination.job.cancel') && <button className="abort" onClick={cancelScout}>ABORT</button>}
          {scanJob.job_status !== 'running' && <button className="dismiss" onClick={() => setScanJob(null)}>DISMISS</button>}
        </section>}

        <section className="workspace">
          <div className="roster panel">
            <div className="panel-head"><div><span className="kicker">NODE ROSTER</span><h2>Connected systems</h2></div><span className="count">{nodes.length}</span></div>
            <label className="search"><span>⌕</span><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter nodes or capabilities" /></label>
            <div className="node-list">
              {nodes.map((node) => <button key={node.device_id} onClick={() => { setSelectedId(node.device_id); setResult(null) }} className={`node-row ${node.device_id === selected?.device_id ? 'selected' : ''}`}>
                <NodeGlyph node={node} /><span className="node-copy"><strong>{node.device_id}</strong><small>{node.device_type} · {node.address}</small></span>
                <span className="node-tail"><i className={node.status} />{node.local ? 'LOCAL' : timeAgo(node.age_seconds)}</span>
              </button>)}
              {!nodes.length && <div className="empty"><span>⌁</span><strong>No matching signals</strong><small>Clear the filter or wait for discovery.</small></div>}
            </div>
          </div>

          <div className="detail panel">
            {selected ? <>
              <div className="detail-head"><NodeGlyph node={selected} /><div><span className="kicker">SELECTED NODE</span><h2>{selected.device_id}</h2><p>{selected.device_type} · firmware {selected.firmware}</p></div><span className={`status-pill ${selected.status}`}><i />{selected.status}</span></div>
              <div className="facts">
                <div><small>ENDPOINT</small><strong>{selected.address}:{selected.port}</strong></div>
                <div><small>LINK PROFILE</small><strong>{selected.resources.network_mbps ? `${selected.resources.network_mbps} Mbps` : 'Unreported'}</strong></div>
                <div><small>STORAGE FREE</small><strong>{bytes(selected.resources.storage_free_bytes)}</strong></div>
                <div><small>ROLES</small><strong>{selected.roles.join(' / ')}</strong></div>
                <div><small>TRUST</small><strong>{selected.security?.paired ? selected.security.mode ?? 'Paired' : 'Public / unpaired'}</strong></div>
                <div><small>ACTIVE COORDINATOR</small><strong>{selected.security?.active_coordinator ? `${selected.security.active_coordinator} · P${selected.security.active_priority}` : selected.security?.primary_coordinator ?? 'None leased'}</strong></div>
              </div>
              <div className="cap-head"><div><span className="kicker">CAPABILITY MATRIX</span><h3>Available actions</h3></div><span>{selected.capabilities.length} advertised</span></div>
              <div className="capabilities">
                {selected.capabilities.map((capability) => {
                  const meta = capabilityMeta(selected, capability)
                  const isScout = capability === 'net.discovery.scan'
                  const directlyInvokable = capability === 'system.info' || capability === 'desktop.resources' || capability === 'coordination.job.status' || capability === 'net.connectivity.check' || capability === 'net.arp.snapshot'
                  return <article key={capability}>
                    <div className="cap-sigil">{capability.split('.').map((part) => part[0]).join('').slice(0, 2).toUpperCase()}</div>
                    <div className="cap-copy"><strong>{capability}</strong><span>v{meta.version} · {meta.permission}</span>{meta.features?.length ? <small>{meta.features.join(' · ')}</small> : null}</div>
                    <button disabled={(!directlyInvokable && !isScout) || !!busyCapability || (isScout && scanJob?.job_status === 'running')} onClick={() => isScout ? configureScout() : invoke(capability)}>{busyCapability === capability ? 'CALLING…' : isScout ? 'CONFIGURE' : directlyInvokable ? 'INVOKE' : 'PLANNED'}</button>
                  </article>
                })}
              </div>
              {result && <div className="result"><div><span className="kicker">LATEST RESPONSE</span><button onClick={() => setResult(null)}>CLOSE</button></div><pre>{JSON.stringify(result, null, 2)}</pre></div>}
            </> : <div className="empty large"><span>⌁</span><strong>Waiting for constellation</strong><small>Reconclave nodes will appear here as they announce.</small></div>}
          </div>

          <div className="activity panel">
            <div className="panel-head"><div><span className="kicker">ACTIVITY STREAM</span><h2>Recent operations</h2></div><span className="live-tag"><i />LIVE</span></div>
            <div className="timeline">
              {activity.map((item) => <article key={item.id}><i className={item.tone} /><div><strong>{item.title}</strong><p>{item.detail}</p></div><time>{item.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</time></article>)}
              {!activity.length && <div className="empty"><span>∿</span><strong>Channel is quiet</strong><small>Node commands and job events will appear here.</small></div>}
            </div>
          </div>
        </section>
      </> : <WorkspaceViews view={view} workspace={workspace} nodes={state.nodes} projectId={projectId} onProject={setProjectId} onCreate={createProject} onInspect={inspectSelectedHosts} onCreateAutomation={createAutomation} onUpdateAutomation={updateAutomation} onDeleteAutomation={deleteAutomation} onCreateWorkflow={createWorkflow} onRunWorkflow={runWorkflow} onCancelWorkflow={cancelWorkflow} onUpdateWorkflow={updateWorkflow} onDeleteWorkflow={deleteWorkflow} onCreateScope={createScope} onImportFindings={importFindings} onCorrelateFindings={correlateFindings} onSetFindingStatus={setFindingStatus} onSetFindingSuppression={setFindingSuppression} onCreateRelease={createRelease} onCreateRollout={createRollout} onAdvanceRollout={advanceRollout} onRollbackRollout={rollbackRollout} onCreateDistributedScan={createDistributedScan} onCancelDistributedScan={cancelDistributedScan} currentOperator={session?.operator ?? null} onCreateOperator={createOperator} onDecideApproval={decideApproval} />}</main>
      {scoutOpen && selected && <div className="modal-shade" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setScoutOpen(false) }}>
        <section className="scout-modal" role="dialog" aria-modal="true" aria-labelledby="scout-title">
          <div className="modal-head"><div><span className="kicker">SCOPED OPERATION</span><h2 id="scout-title">Configure Network Scout</h2><p>Provider: {selected.device_id}</p></div><button onClick={() => setScoutOpen(false)} aria-label="Close">×</button></div>
          <div className="scope-visual"><span>{scope.start || 'START'}</span><div><i /><i /><i /><i /><i /></div><span>{scope.end || 'END'}</span></div>
          <label className="field"><span>NETWORK / CIDR</span><input value={scope.network} onChange={(event) => setScope({ ...scope, network: event.target.value })} placeholder="192.168.1.0/24" /></label>
          <label className="field"><span>PROJECT</span><select value={projectId} onChange={(event) => setProjectId(event.target.value)}><option value="">Run without archiving</option>{workspace.projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>
          <div className="field-pair">
            <label className="field"><span>FIRST ADDRESS</span><input value={scope.start} onChange={(event) => setScope({ ...scope, start: event.target.value })} /></label>
            <label className="field"><span>LAST ADDRESS</span><input value={scope.end} onChange={(event) => setScope({ ...scope, end: event.target.value })} /></label>
          </div>
          <label className="field"><span>RECURRING</span><select value={recurringMinutes} onChange={(event) => setRecurringMinutes(Number(event.target.value))}><option value={0}>One-time operation</option><option value={1}>Every minute</option><option value={5}>Every 5 minutes</option><option value={15}>Every 15 minutes</option><option value={60}>Every hour</option></select></label>
          <div className="scope-note"><strong>BOUNDARY ENFORCEMENT</strong><p>The coordinator permits IPv4 /24 or smaller. The provider independently verifies that this scope is locally attached.</p></div>
          <label className="authorise"><input type="checkbox" checked={authorised} onChange={(event) => setAuthorised(event.target.checked)} /><span><strong>I confirm this network is authorised for assessment.</strong><small>This acknowledgement is required for every dispatched Scout operation.</small></span></label>
          {scoutError && <div className="modal-error"><strong>DISPATCH REFUSED</strong><span>{scoutError}</span></div>}
          <div className="modal-actions"><button className="secondary" onClick={() => setScoutOpen(false)}>CANCEL</button><button className="primary" disabled={!authorised || !scope.network || !scope.start || !scope.end || !!busyCapability} onClick={startScout}>{busyCapability ? 'DISPATCHING…' : 'DISPATCH SCOUT'}</button></div>
        </section>
      </div>}
    </div>
  )
}

export default App
