export type CapabilityDescriptor = {
  id: string
  version: number
  permission: 'public' | 'trusted'
  features?: string[]
  limits?: { weight?: number; max_concurrency?: number }
}

export type ReconNode = {
  device_id: string
  device_type: string
  firmware: string
  roles: string[]
  capabilities: string[]
  capability_descriptors: CapabilityDescriptor[]
  resources: {
    network_mbps?: number
    persistent_storage?: boolean
    storage_free_bytes?: number
  }
  security?: {
    paired?: boolean
    mode?: string
    primary_coordinator?: string
    coordinator_priority?: number
    active_coordinator?: string
    active_priority?: number
    lease_remaining_ms?: number
  }
  status: 'ready' | 'busy' | 'degraded'
  address: string
  port: number
  age_seconds: number
  local: boolean
}

export type AppState = {
  revision: number
  nodes: ReconNode[]
  coordinator_id: string
  updated_at_ms: number
}

export type Activity = {
  id: string
  time: Date
  title: string
  detail: string
  tone: 'ok' | 'warn' | 'info'
}

export type ScanJob = {
  archiveId?: string
  projectId?: string
  scope?: { network: string; start: string; end: string }
  providerId: string
  job_id?: string | number
  job_status: 'idle' | 'running' | 'complete' | 'failed' | 'stopped'
  checked: number
  total: number
  hosts: string[]
  error?: string
  recurring?: boolean
  run_count?: number
}

export type Project = { id: string; name: string; description: string; created_at_ms: number; updated_at_ms: number }
export type ArchivedJob = { id: string; project_id: string; provider_id?: string; capability?: string; status?: string; checked?: number; total?: number; hosts?: string[]; scope?: Record<string, string>; error?: string; created_at_ms: number; updated_at_ms: number }
export type EvidenceHost = string | { address: string; open_ports?: number[]; checked_ports?: number }
export type EvidenceRecord = { id: string; project_id: string; job_id?: string; kind: string; title: string; summary: string; data?: { hosts?: EvidenceHost[]; [key: string]: unknown }; captured_at_ms: number }
export type AutomationRule = { id: string; project_id: string; node_id: string; condition: 'dhcp_assigned' | 'internet_possible'; playbook: 'network_scout' | 'system_snapshot'; interval_ms: number; enabled: boolean; device_managed?: boolean; created_at_ms: number; updated_at_ms: number; last_triggered_ms: number; last_error: string }
export type WorkflowStep = { id: string; capability: string; arguments: Record<string, unknown>; depends_on: string[]; preferred_node?: string; retries: number; timeout_ms: number }
export type Workflow = { id: string; project_id: string; name: string; description: string; steps: WorkflowStep[]; created_at_ms: number; updated_at_ms: number }
export type WorkflowStepRun = { id: string; status: 'pending' | 'running' | 'complete' | 'failed' | 'cancelled'; attempts: number; node_id: string; result?: unknown; error?: string; started_at_ms: number }
export type WorkflowRun = { id: string; workflow_id: string; project_id: string; status: 'queued' | 'running' | 'complete' | 'failed' | 'cancelled'; steps: WorkflowStepRun[]; created_at_ms: number; updated_at_ms: number }
export type EngagementScope = { id: string; project_id: string; revision: number; included_networks: string[]; excluded_networks: string[]; capability_classes: string[]; expires_at_ms: number; signature: string }
export type AuditEvent = { id: string; trace_id?: string; actor_id?: string; project_id: string; action: string; subject_id: string; outcome: string; created_at_ms: number; node_id?: string; condition?: string }
export type FindingStatus = 'open' | 'candidate' | 'confirmed-observed' | 'confirmed' | 'false_positive' | 'remediated'
export type RemediationStatus = 'open' | 'in_progress' | 'done'
export type FindingRemediation = { owner: string; due_at_ms: number; notes: string; status: RemediationStatus }
export type Finding = { id: string; project_id: string; source: string; plugin_id: string; title: string; target: string; port?: number; severity: string; confidence: number; risk_score: number; description: string; solution: string; cves: string[]; status: FindingStatus; suppressed?: boolean; suppression_reason?: string; suppressed_at_ms?: number; remediation?: FindingRemediation; provenance?: { evidence_id?: string; job_id?: string; matched_template_id?: string; match_basis?: string; observed_service?: string }; first_seen_ms: number; last_seen_ms: number }
export type FleetNode = { device_id: string; device_type: string; firmware: string; status: string; address: string; capabilities: string[]; resources: Record<string, unknown>; drift: Record<string, { desired: unknown; actual: unknown }>; first_seen_ms: number; last_seen_ms: number }
export type FleetConfig = { device_type: string; desired: Record<string, unknown>; updated_at_ms: number }
export type OtaRelease = { id: string; device_type: string; version: string; artifact_sha256: string; created_at_ms: number; signature: string }
export type OtaRolloutTarget = { device_id: string; status: string; error: string }
export type OtaRollout = { id: string; release_id: string; previous_release_id?: string; status: string; batch_size: number; failure_threshold: number; targets: OtaRolloutTarget[]; created_at_ms: number; updated_at_ms: number }
export type DistributedScanChunk = { id: string; start_ip: string; end_ip: string; status: 'pending' | 'running' | 'complete' | 'failed' | 'cancelled'; assigned_node: string; fixed_node: boolean; job_id: string; attempts: number; tried_nodes: string[]; result?: { hosts?: string[]; checked?: number; total?: number }; error: string }
export type ConsensusObservation = { node_id: string; detected: boolean }
export type ConsensusTarget = { observations: ConsensusObservation[]; concord: 'high' | 'low' | 'unobserved'; detected_count: number; total_observations: number }
export type DistributedScan = { id: string; project_id: string; scope_id: string; mode: 'parallel' | 'consensus'; capability: string; network: string; max_concurrent_chunks: number; status: 'running' | 'complete' | 'partial' | 'failed' | 'cancelled'; chunks: DistributedScanChunk[]; consensus: { targets: Record<string, ConsensusTarget> } | null; created_at_ms: number; updated_at_ms: number }
export type OperatorRole = 'admin' | 'operator' | 'viewer'
export type PublicOperator = { id: string; username: string; display_name: string; role: OperatorRole; disabled: boolean }
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'failed'
export type Approval = { id: string; action_type: string; payload: Record<string, unknown>; requested_by: string; requested_by_username: string; status: ApprovalStatus; decided_by: string; decided_by_username: string; decided_at_ms: number; result: unknown; error: string; created_at_ms: number }
export type SessionInfo = { auth_required: boolean; operator: PublicOperator | null }
export type WorkspaceData = { revision: number; projects: Project[]; jobs: ArchivedJob[]; evidence: EvidenceRecord[]; automations: AutomationRule[]; workflows: Workflow[]; workflow_runs: WorkflowRun[]; scopes: EngagementScope[]; audit_events: AuditEvent[]; findings: Finding[]; fleet_nodes: FleetNode[]; fleet_configs: FleetConfig[]; ota_releases: OtaRelease[]; ota_rollouts: OtaRollout[]; distributed_scans: DistributedScan[]; operators: PublicOperator[]; approvals: Approval[] }
