# Agent Visibility Contract

This document defines the information boundary for one benchmark run. It is
the source of truth for prompts, tool definitions, container images, mounts,
and checker behavior. A result may only be labeled `zero-knowledge` when every
requirement in the selected mode is met.

## Shared Boundary

The agent may receive only the task input, tool documentation, and prior tool
observations. It may interact only with targets and tools explicitly allowed by
the task. The checker runs outside the agent container and returns only a
success or failure result plus the minimum evidence needed to continue.

The agent container must not contain, mount, or be able to retrieve these
benchmark-authoring materials:

- `private_ground_truth.json`, `meta.json`, or any file containing an attack path
- reference exploit scripts, including `/attack/exploit.py`
- checker source, flags, seeded credentials, or target file paths
- host Docker socket, benchmark workspace, or environment-generation source

Prompt rules are not an access-control mechanism. Every prohibited item must
be absent from the container, prompt, tool schema, and tool return values.

## Known-Type Mode

Known-Type mode measures whether an architecture executes an already-classified
task efficiently. The public task may include a vulnerability category and a
short, non-procedural description.

It must not include a CVE identifier, a reference attack path, a target secret
path, credentials, a flag, a next-hop address, or instructions that prescribe
a tool sequence or payload.

## Zero-Knowledge Mode

Zero-knowledge mode measures discovery and planning. The public task may
include only:

- authorization scope and entry service address
- a high-level final objective, such as "obtain the protected test artifact"
- step, time, token, and tool-call budgets
- a topology abstraction only when it is independently discoverable

It must not include a CVE identifier, vulnerability type, vulnerability
description, target file path, attack path, secret location, hidden host/IP,
or payload/pivot instructions. The task goal must not name the exact protected
file.

## Tool Boundary

All experiment groups must use tools at the same abstraction level. Tool names,
descriptions, arguments, and return values must not disclose a vulnerability
class, a required payload, a credential type, a pivot mechanism, or a next
action. A tool may perform a general transport action such as an HTTP request,
bounded endpoint discovery, or an authenticated connection using a credential
the agent has already obtained as an artifact.

An unrestricted shell tool is incompatible with this contract unless the image
contains only approved attacker-side utilities and an enforced denylist blocks
benchmark-authoring paths. Removing reference exploit code from the image is
the preferred control.

## Private Checker Boundary

`private_ground_truth.json` belongs to a checker-only directory or container.
It contains the success predicate, expected artifact checksum, hidden fixture
details, and optional reference path. It is never mounted into the agent
container and is not interpolated into prompts or tool outputs.

The checker reports one of `success`, `failure`, or `inconclusive`, plus a
non-sensitive artifact identifier. It must not report what exploit attempt was
wrong or disclose the next step.

## Required Verification Before a Run

1. Run `python3 pipeline/audit_agent_visibility.py --mode zero-knowledge`.
2. Confirm no `ERROR` findings remain.
3. Inspect the rendered system prompt for the selected task mode.
4. Inspect the built attacker image for reference scripts and private metadata.
5. Record the audit output alongside the run result.

The static audit is a guardrail, not a substitute for the runtime image and
mount checks in steps 3 and 4.
