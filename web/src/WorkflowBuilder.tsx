import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReconNode, Workflow, WorkflowStep } from './types'

// Layout constants for the canvas -- plain pixel coordinates shared 1:1 between the
// absolutely-positioned step divs and the SVG edges drawn behind them, so pointer math
// never has to account for a scaled viewBox.
const COLUMN_WIDTH = 200
const ROW_HEIGHT = 96
const NODE_WIDTH = 160
const NODE_HEIGHT = 64

const STEP_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/
const CAPABILITY_PATTERN = /^[a-z][a-z0-9]*(?:\.[a-z0-9_-]+)+$/

type Position = { x: number; y: number }

// Longest-path-from-a-root depth per step, used only for the initial auto-layout column
// (steps with no dependencies start at column 0). A step already caught in a cycle just
// falls back to depth 0 for layout purposes -- findCycle() is what actually surfaces that
// as a blocking error, not this.
function stepDepths(steps: WorkflowStep[]): Record<string, number> {
  const byId = new Map(steps.map((step) => [step.id, step]))
  const depth = new Map<string, number>()
  function resolve(id: string, trail: Set<string>): number {
    if (depth.has(id)) return depth.get(id) as number
    if (trail.has(id)) return 0
    const step = byId.get(id)
    if (!step || step.depends_on.length === 0) { depth.set(id, 0); return 0 }
    trail.add(id)
    const value = 1 + Math.max(...step.depends_on.map((dep) => byId.has(dep) ? resolve(dep, trail) : 0))
    trail.delete(id)
    depth.set(id, value)
    return value
  }
  steps.forEach((step) => resolve(step.id, new Set()))
  return Object.fromEntries(depth)
}

function autoLayout(steps: WorkflowStep[]): Record<string, Position> {
  const depths = stepDepths(steps)
  const columns = new Map<number, string[]>()
  steps.forEach((step) => {
    const column = depths[step.id] ?? 0
    columns.set(column, [...(columns.get(column) ?? []), step.id])
  })
  const positions: Record<string, Position> = {}
  columns.forEach((ids, column) => {
    ids.forEach((id, row) => { positions[id] = { x: 40 + column * COLUMN_WIDTH, y: 30 + row * ROW_HEIGHT } })
  })
  return positions
}

// Mirrors WorkspaceStore._validate_workflow_steps' own cycle check so a cycle is caught
// and explained before the operator ever hits "save", not after a rejected request.
function findCycle(steps: WorkflowStep[]): string | null {
  const byId = new Map(steps.map((step) => [step.id, step]))
  const state = new Map<string, 'visiting' | 'done'>()
  function visit(id: string): string | null {
    const status = state.get(id)
    if (status === 'done') return null
    if (status === 'visiting') return id
    state.set(id, 'visiting')
    for (const dep of byId.get(id)?.depends_on ?? []) {
      const cycle = visit(dep)
      if (cycle) return cycle
    }
    state.set(id, 'done')
    return null
  }
  for (const step of steps) {
    const cycle = visit(step.id)
    if (cycle) return cycle
  }
  return null
}

let freshIdCounter = 0
function freshStepId(existing: Set<string>): string {
  let id: string
  do { freshIdCounter += 1; id = `step-${freshIdCounter}` } while (existing.has(id))
  return id
}

const DEFAULT_STEPS: WorkflowStep[] = [
  { id: 'system', capability: 'system.info', arguments: {}, depends_on: [], retries: 1, timeout_ms: 300000 },
  { id: 'connectivity', capability: 'net.connectivity.check', arguments: {}, depends_on: ['system'], retries: 1, timeout_ms: 300000 },
]

export default function WorkflowBuilder({ workflow, nodes, onSave, onClose }: {
  workflow: Workflow | null
  nodes: ReconNode[]
  onSave: (body: { name: string; description: string; steps: WorkflowStep[] }) => Promise<void>
  onClose: () => void
}) {
  const [name, setName] = useState(workflow?.name ?? '')
  const [description, setDescription] = useState(workflow?.description ?? '')
  const [steps, setSteps] = useState<WorkflowStep[]>(() =>
    (workflow?.steps ?? DEFAULT_STEPS).map((step) => ({ ...step, arguments: { ...step.arguments } })))
  const [positions, setPositions] = useState<Record<string, Position>>({})
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [argumentsDraft, setArgumentsDraft] = useState('{}')
  const [argumentsError, setArgumentsError] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [connectPreview, setConnectPreview] = useState<Position | null>(null)
  const dragRef = useRef<{ id: string; offsetX: number; offsetY: number; moved: boolean } | null>(null)
  const [connectingFrom, setConnectingFrom] = useState<string | null>(null)
  const canvasRef = useRef<HTMLDivElement | null>(null)

  const autoPositions = useMemo(() => autoLayout(steps), [steps])
  const resolvedPositions = useMemo(() => {
    const merged: Record<string, Position> = {}
    steps.forEach((step) => { merged[step.id] = positions[step.id] ?? autoPositions[step.id] ?? { x: 40, y: 30 } })
    return merged
  }, [steps, positions, autoPositions])

  const capabilitySuggestions = useMemo(() => {
    const values = new Set<string>()
    nodes.forEach((node) => node.capabilities.forEach((capability) => values.add(capability)))
    return Array.from(values).sort()
  }, [nodes])

  const selected = steps.find((step) => step.id === selectedId) ?? null

  // Changing which step is selected also has to reset the arguments-JSON draft/error --
  // done here, synchronously in the same event handler that changes the selection,
  // rather than via a useEffect keyed on selectedId (which would run a render behind,
  // cascading an extra render for no benefit). `forStep` covers the two call sites where
  // the step being selected doesn't exist under its new id in `steps` yet (a step just
  // created or renamed in this same handler).
  function selectStep(id: string | null, forStep?: WorkflowStep) {
    setSelectedId(id)
    const step = forStep ?? steps.find((item) => item.id === id) ?? null
    setArgumentsDraft(step ? JSON.stringify(step.arguments, null, 2) : '{}')
    setArgumentsError('')
  }

  function updateStep(id: string, patch: Partial<WorkflowStep>) {
    setSteps((current) => current.map((step) => step.id === id ? { ...step, ...patch } : step))
  }

  function addStep() {
    const id = freshStepId(new Set(steps.map((step) => step.id)))
    const created: WorkflowStep = { id, capability: 'system.info', arguments: {}, depends_on: [], retries: 0, timeout_ms: 300000 }
    setSteps((current) => [...current, created])
    selectStep(id, created)
  }

  function removeStep(id: string) {
    setSteps((current) => current.filter((step) => step.id !== id)
      .map((step) => ({ ...step, depends_on: step.depends_on.filter((dep) => dep !== id) })))
    setPositions((current) => { const next = { ...current }; delete next[id]; return next })
    if (selectedId === id) selectStep(null)
  }

  function renameStep(id: string, nextId: string) {
    if (!nextId || nextId === id) return
    const original = steps.find((step) => step.id === id)
    setSteps((current) => current.map((step) => step.id === id
      ? { ...step, id: nextId }
      : { ...step, depends_on: step.depends_on.map((dep) => dep === id ? nextId : dep) }))
    setPositions((current) => { const next = { ...current }; if (id in next) { next[nextId] = next[id]; delete next[id] } return next })
    selectStep(nextId, original ? { ...original, id: nextId } : undefined)
  }

  // Rejects a dependency that would self-reference or complete a cycle, silently --
  // canSave's own cycle check still runs so nothing already-invalid gets stuck displayed.
  function addDependency(dependentId: string, dependencyId: string) {
    if (dependentId === dependencyId) return
    setSteps((current) => {
      const target = current.find((step) => step.id === dependentId)
      if (!target || target.depends_on.includes(dependencyId)) return current
      const next = current.map((step) => step.id === dependentId
        ? { ...step, depends_on: [...step.depends_on, dependencyId] } : step)
      return findCycle(next) ? current : next
    })
  }

  function removeDependency(dependentId: string, dependencyId: string) {
    setSteps((current) => current.map((step) => step.id === dependentId
      ? { ...step, depends_on: step.depends_on.filter((dep) => dep !== dependencyId) } : step))
  }

  function canvasPoint(event: { clientX: number; clientY: number }): Position | null {
    const canvas = canvasRef.current
    if (!canvas) return null
    const bounds = canvas.getBoundingClientRect()
    return { x: event.clientX - bounds.left + canvas.scrollLeft, y: event.clientY - bounds.top + canvas.scrollTop }
  }

  function beginDrag(id: string, event: React.PointerEvent) {
    const point = canvasPoint(event)
    const position = resolvedPositions[id]
    if (!point || !position) return
    dragRef.current = { id, moved: false, offsetX: point.x - position.x, offsetY: point.y - position.y }
  }

  function endDragAsClick(id: string) {
    if (dragRef.current && dragRef.current.id === id && !dragRef.current.moved) selectStep(id)
  }

  // Both dragging (repositioning) and connecting (drag from a step's output handle onto
  // another step) need window-level listeners: the pointer routinely leaves the
  // originating element mid-drag, and a plain per-element handler would lose the drag.
  useEffect(() => {
    function handleMove(event: PointerEvent) {
      const point = canvasPoint(event)
      if (!point) return
      if (dragRef.current) {
        dragRef.current.moved = true
        const { id, offsetX, offsetY } = dragRef.current
        setPositions((current) => ({ ...current, [id]: { x: point.x - offsetX, y: point.y - offsetY } }))
      } else if (connectingFrom) {
        setConnectPreview(point)
      }
    }
    function handleUp(event: PointerEvent) {
      if (connectingFrom) {
        const point = canvasPoint(event)
        const from = connectingFrom
        if (point) {
          const target = steps.find((step) => {
            const position = resolvedPositions[step.id]
            return position && point.x >= position.x && point.x <= position.x + NODE_WIDTH &&
              point.y >= position.y && point.y <= position.y + NODE_HEIGHT
          })
          if (target) addDependency(target.id, from)
        }
        setConnectingFrom(null)
        setConnectPreview(null)
      }
      dragRef.current = null
    }
    window.addEventListener('pointermove', handleMove)
    window.addEventListener('pointerup', handleUp)
    return () => { window.removeEventListener('pointermove', handleMove); window.removeEventListener('pointerup', handleUp) }
  }, [steps, resolvedPositions, connectingFrom])

  const cycleStepId = useMemo(() => findCycle(steps), [steps])
  const duplicateIds = useMemo(() => {
    const seen = new Set<string>()
    const dupes = new Set<string>()
    steps.forEach((step) => { if (seen.has(step.id)) dupes.add(step.id); seen.add(step.id) })
    return dupes
  }, [steps])
  const invalidIds = useMemo(() => new Set(steps.filter((step) => !STEP_ID_PATTERN.test(step.id)).map((step) => step.id)), [steps])
  const invalidCapabilities = useMemo(() =>
    new Set(steps.filter((step) => !CAPABILITY_PATTERN.test(step.capability)).map((step) => step.id)), [steps])
  const invalidRetries = steps.some((step) => !(step.retries >= 0 && step.retries <= 3))
  const invalidTimeouts = steps.some((step) => !(step.timeout_ms >= 1000 && step.timeout_ms <= 3600000))
  const canSave = name.trim().length > 0 && name.trim().length <= 80 && steps.length >= 1 && steps.length <= 32 &&
    !cycleStepId && duplicateIds.size === 0 && invalidIds.size === 0 && invalidCapabilities.size === 0 &&
    !invalidRetries && !invalidTimeouts && !argumentsError

  async function handleSave() {
    setError('')
    setSaving(true)
    try {
      await onSave({ name: name.trim(), description: description.trim(), steps })
      onClose()
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Could not save workflow')
    } finally {
      setSaving(false)
    }
  }

  const canvasWidth = Math.max(560, ...Object.values(resolvedPositions).map((position) => position.x + NODE_WIDTH + 80))
  const canvasHeight = Math.max(280, ...Object.values(resolvedPositions).map((position) => position.y + NODE_HEIGHT + 40))

  return <div className="modal-shade" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <section className="scout-modal workflow-builder" role="dialog" aria-modal="true" aria-labelledby="workflow-builder-title">
      <div className="modal-head">
        <div>
          <span className="kicker">WORKFLOW AUTOMATION</span>
          <h2 id="workflow-builder-title">{workflow ? 'Edit workflow' : 'New workflow'}</h2>
          <p>Drag a step to reposition it. Drag from a step's right-edge handle onto another step to make that step depend on it.</p>
        </div>
        <button onClick={onClose} aria-label="Close">×</button>
      </div>
      <div className="field-pair">
        <label className="field"><span>NAME</span><input value={name} onChange={(event) => setName(event.target.value)} maxLength={80} /></label>
        <label className="field"><span>DESCRIPTION</span><input value={description} onChange={(event) => setDescription(event.target.value)} maxLength={500} /></label>
      </div>
      <div className="workflow-builder-body">
        <div className="workflow-canvas-wrap">
          <div className="workflow-toolbar"><button className="primary-action" onClick={addStep} disabled={steps.length >= 32}>+ ADD STEP</button><small>{steps.length}/32 steps</small></div>
          <div className="workflow-canvas" ref={canvasRef}>
            <svg className="workflow-edges" width={canvasWidth} height={canvasHeight}>
              <defs><marker id="wf-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="var(--cyan-dim)" /></marker></defs>
              {steps.flatMap((step) => step.depends_on.map((depId) => {
                const from = resolvedPositions[depId]
                const to = resolvedPositions[step.id]
                if (!from || !to) return null
                const x1 = from.x + NODE_WIDTH, y1 = from.y + NODE_HEIGHT / 2
                const x2 = to.x, y2 = to.y + NODE_HEIGHT / 2
                const midX = (x1 + x2) / 2
                const path = `M${x1},${y1} C${midX},${y1} ${midX},${y2} ${x2},${y2}`
                return <g key={`${depId}->${step.id}`} className="workflow-edge">
                  <path d={path} fill="none" stroke="transparent" strokeWidth={10} onClick={() => removeDependency(step.id, depId)} />
                  <path d={path} fill="none" stroke="var(--cyan-dim)" strokeWidth={1.4} markerEnd="url(#wf-arrow)" />
                </g>
              }))}
              {connectPreview && connectingFrom && resolvedPositions[connectingFrom] && (() => {
                const from = resolvedPositions[connectingFrom]
                return <line className="workflow-edge-preview" x1={from.x + NODE_WIDTH} y1={from.y + NODE_HEIGHT / 2} x2={connectPreview.x} y2={connectPreview.y} />
              })()}
            </svg>
            {steps.map((step) => {
              const position = resolvedPositions[step.id]
              if (!position) return null
              const invalid = invalidIds.has(step.id) || duplicateIds.has(step.id) || cycleStepId === step.id
              return <div key={step.id}
                className={`workflow-node ${selectedId === step.id ? 'selected' : ''} ${invalid ? 'invalid' : ''}`}
                style={{ left: position.x, top: position.y, width: NODE_WIDTH, height: NODE_HEIGHT }}
                onPointerDown={(event) => beginDrag(step.id, event)}
                onPointerUp={() => endDragAsClick(step.id)}>
                <strong>{step.id}</strong>
                <span>{step.capability || '(no capability)'}</span>
                <button className="workflow-node-remove" title="Remove step" aria-label={`Remove step ${step.id}`}
                  onPointerDown={(event) => event.stopPropagation()}
                  onClick={(event) => { event.stopPropagation(); removeStep(step.id) }}>×</button>
                <span className="workflow-node-handle" title="Drag onto another step to make it depend on this one"
                  onPointerDown={(event) => {
                    event.stopPropagation()
                    setConnectingFrom(step.id)
                    setConnectPreview({ x: position.x + NODE_WIDTH, y: position.y + NODE_HEIGHT / 2 })
                  }} />
              </div>
            })}
          </div>
        </div>
        <div className="workflow-step-editor">
          {!selected && <div className="empty"><span>◇</span><strong>No step selected</strong><small>Click a step on the canvas to edit it.</small></div>}
          {selected && <>
            <label className="field"><span>STEP ID</span><input value={selected.id}
              onChange={(event) => renameStep(selected.id, event.target.value.trim())} /></label>
            <label className="field"><span>CAPABILITY</span>
              <input list="workflow-capability-options" value={selected.capability}
                onChange={(event) => updateStep(selected.id, { capability: event.target.value.trim() })} />
            </label>
            <datalist id="workflow-capability-options">{capabilitySuggestions.map((capability) => <option key={capability} value={capability} />)}</datalist>
            <label className="field"><span>PREFERRED NODE</span>
              <select value={selected.preferred_node ?? ''} onChange={(event) => updateStep(selected.id, { preferred_node: event.target.value })}>
                <option value="">Any capable node</option>
                {nodes.map((node) => <option key={node.device_id} value={node.device_id}>{node.device_id}</option>)}
              </select>
            </label>
            <div className="field-pair">
              <label className="field"><span>RETRIES (0-3)</span>
                <input type="number" min={0} max={3} value={selected.retries}
                  onChange={(event) => updateStep(selected.id, { retries: Number(event.target.value) })} />
              </label>
              <label className="field"><span>TIMEOUT (MS)</span>
                <input type="number" min={1000} max={3600000} value={selected.timeout_ms}
                  onChange={(event) => updateStep(selected.id, { timeout_ms: Number(event.target.value) })} />
              </label>
            </div>
            <label className="field"><span>DEPENDS ON</span>
              <div className="workflow-dependency-list">
                {steps.filter((step) => step.id !== selected.id).map((step) => <label key={step.id} className="workflow-dependency-option">
                  <input type="checkbox" checked={selected.depends_on.includes(step.id)}
                    onChange={(event) => event.target.checked ? addDependency(selected.id, step.id) : removeDependency(selected.id, step.id)} />
                  {step.id}
                </label>)}
                {steps.length <= 1 && <small>Add another step to create a dependency.</small>}
              </div>
            </label>
            <label className="field"><span>ARGUMENTS (JSON)</span>
              <textarea className="workflow-arguments" rows={6} value={argumentsDraft}
                onChange={(event) => {
                  setArgumentsDraft(event.target.value)
                  try { updateStep(selected.id, { arguments: JSON.parse(event.target.value || '{}') }); setArgumentsError('') }
                  catch { setArgumentsError('Arguments must be valid JSON') }
                }} />
              {argumentsError && <small className="inspection-error">{argumentsError}</small>}
            </label>
          </>}
        </div>
      </div>
      {cycleStepId && <div className="modal-error"><strong>DEPENDENCY CYCLE</strong><span>Step "{cycleStepId}" is part of a dependency cycle — remove one of its edges.</span></div>}
      {duplicateIds.size > 0 && <div className="modal-error"><strong>DUPLICATE STEP ID</strong><span>{Array.from(duplicateIds).join(', ')}</span></div>}
      {(invalidIds.size > 0 || invalidCapabilities.size > 0) && <div className="modal-error"><strong>INVALID STEP</strong><span>Step ids must match [a-z0-9][a-z0-9_-]* and capabilities must look like a.b.c.</span></div>}
      {error && <div className="modal-error"><strong>SAVE FAILED</strong><span>{error}</span></div>}
      <div className="modal-actions">
        <button className="secondary" onClick={onClose}>CANCEL</button>
        <button className="primary" disabled={!canSave || saving} onClick={handleSave}>{saving ? 'SAVING…' : workflow ? 'SAVE CHANGES' : 'CREATE WORKFLOW'}</button>
      </div>
    </section>
  </div>
}
