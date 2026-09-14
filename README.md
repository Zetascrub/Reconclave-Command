# Reconclave Command

**The desktop coordinator for the Reconclave collective.**

Reconclave Command plans work, discovers cooperating nodes, dispatches tasks,
and keeps assessment evidence and operational history together. It also runs as
a standalone local application without a hardware fleet.

> Use Reconclave Command only for systems and networks you own or are explicitly
> authorised to assess.

## Relationship to Reconclave

- **Standalone:** local projects, workflows, analysis, evidence custody, and
  operator controls are useful without attached devices.
- **Collective:** Command is the preferred high-priority coordinator for
  FieldDeck, Relay, Sightline, ZetaDongle, and future compatible nodes.
- **Shared identity:** `shared/identity/` is a vendored snapshot of the style
  tokens defined by [Reconclave](https://github.com/Zetascrub/Reconclave).
- **Protocol authority:** wire schemas, capability naming, trust boundaries, and
  product-family guidance remain canonical in the Reconclave repository.

## Application capabilities

## Web coordinator

The desktop web application is the recommended interactive runtime. It acts as
a node, coordinator, or both; discovers `_reconclave._tcp.local` peers; expires
stale nodes after 45 seconds; presents capability and resource metadata; and
can invoke safe inspection capabilities from a live node detail view.

Build the React interface once, then start the local application:

```bash
./start.sh
```

Or prepare and run each layer manually:

```bash
python3 -m venv .venv-desktop-node
.venv-desktop-node/bin/pip install -r requirements.txt
cd web
npm ci
npm run build
cd ..
.venv-desktop-node/bin/python desktop_app.py --mode both
```

Open <http://127.0.0.1:8767>. The live roster and command API are deliberately
loopback-only. The Reconclave announcement and message endpoints remain
available to other nodes on the LAN.

Trusted capability requests accept environment variables. Do not type secret
values directly into commands: shell history can retain inline assignments.
For an interactive Bash session, read them without echo:

```bash
read -r -s -p 'Execution key: ' RECONCLAVE_EXECUTION_KEY; printf '\n'
read -r -s -p 'Evidence key: ' RECONCLAVE_EVIDENCE_KEY; printf '\n'
export RECONCLAVE_EXECUTION_KEY RECONCLAVE_EVIDENCE_KEY
.venv-desktop-node/bin/python desktop_app.py --mode both \
  --enable-network-scan --evidence-dir ./evidence
unset RECONCLAVE_EXECUTION_KEY RECONCLAVE_EVIDENCE_KEY
```

The UI directly invokes `system.info`, `desktop.resources`, and
`coordination.job.status`. Selecting `net.discovery.scan` opens the Scout
configuration workflow. It derives a suggested `/24` from the provider,
requires an explicit authorization acknowledgement, and shows live progress
and responsive hosts. The backend independently rejects missing
acknowledgements, IPv6, scopes broader than `/24`, reversed ranges, and network
or broadcast addresses. Providers still enforce their own attached-network
scope before execution.

The primary rail also provides persistent **Projects**, **Jobs**, **Evidence**,
and **Map** workspaces. Create a project before dispatching Scout to archive its
job lifecycle and a deduplicated network-host evidence summary. Map view can be
switched between an interactive node graph and a sortable/filterable list.
Selecting one host reveals its identity, status, capabilities, prior evidence,
and latest observed ports; multiple hosts can be selected for a bounded TCP
inspection using common, web, or custom port sets. Inspection is limited to 16
hosts and 128 ports on the desktop's attached `/24`, requires an explicit
authorisation acknowledgement, and archives its job and evidence in the active
project. Evidence cards open a full structured-data viewer.

The **Rules** workspace manages condition-driven P4 operations. It can react to
a DHCP address becoming available or to the P4's conservative Internet-possible
signal, then capture a system snapshot or launch a bounded Network Scout. Scout
can be one-shot or recurring. These are typed built-in playbooks rather than
arbitrary executable payloads; rule creation requires an explicit authorisation
acknowledgement and the backend independently enforces the allowlist.
On supporting nodes the rule itself is saved to device NVS, with the desktop
record acting as a management mirror. The device can therefore trigger after a
cold boot while every coordinator is offline. Results remain in its durable
outbox until the desktop imports them into the assigned project and acknowledges
receipt.

The **Fleet** workspace spans the whole deployment rather than one project: live
node inventory with desired-vs-actual config drift, signed OTA release
publishing (`device_type`, version, artifact SHA-256, HMAC-signed locally),
and staged batch rollout with per-target verification, a failure-threshold
rollback trigger, and an explicit rollback action reverting already-updated
targets to whichever release preceded the current rollout for that
`device_type`. Cardputer and P4 source implement `fleet.ota.apply`; interoperability
and recovery must be validated on the target deployment. This coordinator's
HMAC release records are separate from the detached Ed25519 publisher signatures
in [release tooling](https://github.com/Zetascrub/Reconclave/blob/main/docs/releasing.md), which devices do not yet enforce.

Workspace metadata is written
atomically to the ignored `.reconclave-data/workspace.json` file with owner-only
permissions; override it with `--workspace-store` when a separate case store is
required.

The coordinator actively revalidates discovered nodes every 12 seconds rather
than treating the initial mDNS callback as a permanent health signal. Active
Scout state and recent activity are retained in browser-local storage, so a
page refresh resumes status polling instead of presenting an empty session.
Protocol-level `rejected` and `error` responses are shown as failures even
though the HTTP transport itself succeeded.

The current fleet profile provisions distinct desktop-P4, Cardputer-P4, and
desktop-Cardputer keys at flash time. Start the desktop with the default ignored
`.reconclave-provisioning/fleet.json` store (or pass `--trust-store`). The P4 can
therefore authenticate the desktop primary and Cardputer secondary without a
Grove connection or a shared fleet-wide secret. See
[Reconclave trust architecture](https://github.com/Zetascrub/Reconclave/blob/main/docs/trust-architecture.md) for generation,
rotation, and limitations.

For UI development, run `npm run dev` in `web/` while `desktop_app.py` is
running; Vite proxies `/api` requests to port 8767.

## Headless node

This read-only Python node advertises itself over mDNS, serves a Reconclave v1
announcement, and implements `system.info`, `desktop.resources`, and bounded
local-network discovery (`net.discovery.scan` plus `coordination.job.status`
and `coordination.job.cancel`) capabilities. Its announcement is generated
from the live capability-handler registry, preventing it from advertising
handlers it does not provide. It does not execute commands or expose
unrestricted assessment capabilities.

`--enable-tools` opts a keyed desktop node into fixed packaged assessment
adapters. Adapters are advertised only when their executable is installed and
never expose a shell. The initial `tool.nmap.services` adapter accepts at most
32 literal IP addresses and 128 ports, performs a TCP connect scan without NSE
scripts or OS detection, and returns normalised XML-derived observations.
Coordinator dispatch also requires a current signed engagement scope that
contains every target.

Network discovery is restricted to an IPv4 `/24` or smaller. It checks a small
set of common TCP services and treats either a connection or an explicit refusal
as evidence that a host is present. Only scan networks you own or are authorised
to assess. It is disabled by default; explicitly enable it with:

```bash
.venv-desktop-node/bin/python reconclave_node.py \
    --enable-network-scan --execution-key "shared execution passphrase"
```

When enabled, the desktop appears automatically among the Cardputer Scout
providers. The scan capability is only registered when both the flag and a
execution key are present; otherwise it is neither advertised nor callable.

`net.discovery.scan` accepts an optional `schedule: {"interval_ms": N,
"after_completion": true}` argument to run repeatedly until stopped with
`coordination.job.cancel`; `coordination.job.status` then reports `recurring`
and `run_count`. See `docs/capabilities.md` for the full contract.

Passing `--evidence-dir PATH` advertises `storage.evidence.write`, making this
node an Evidence Collector: any coordinator that knows about it will forward a
copy of evidence it produces or observes, appended as JSON Lines under
`PATH/evidence-YYYYMMDD.jsonl`. `net.discovery.scan`,
`storage.evidence.write`, and `coordination.job.cancel` assess or change
external state. Scan and job control require `--execution-key`; evidence custody
requires the separate `--evidence-key`. Each must match the corresponding key on
the coordinator (Cardputer: Settings > Trust). Every request is signed and checked against
recently-seen nonces; an unsigned, wrongly-signed, or replayed request is
rejected with `UNAUTHENTICATED`. See "Authenticated capabilities" in
`docs/capabilities.md` for the exact signature scheme.

```bash
.venv-desktop-node/bin/python reconclave_node.py \
    --enable-network-scan --execution-key "execution passphrase" \
    --evidence-dir ~/reconclave-evidence --evidence-key "evidence passphrase"
```

Create an isolated environment and run it from the repository root:

```bash
python3 -m venv .venv-desktop-node
.venv-desktop-node/bin/pip install -r requirements.txt
.venv-desktop-node/bin/python reconclave_node.py
```

Open **Reconclave** on the Cardputer and use its refresh action. The machine
should appear as `desktop-node`. The default identity is stable for that
machine; override it with `--node-id` if required.

If the wrong interface is selected on a multi-homed computer, pass its LAN
address explicitly:

```bash
.venv-desktop-node/bin/python reconclave_node.py --address 192.168.1.20
```

The host firewall must permit inbound TCP on port 8767 and mDNS/UDP 5353 on the
local network. Use `Ctrl-C` for a clean shutdown.
