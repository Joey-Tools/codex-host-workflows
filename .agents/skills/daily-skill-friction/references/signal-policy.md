# Signal Policy

## Evidence Unit

Treat a human root task as the user's substantive objective across its root Codex
task and genuine follow-ups. Count observed opportunities, not messages, error
lines, tool calls, subagents, or retries.

A single root task may contribute more than one recurrence only when the timeline
shows that the human workflow reached a new real opportunity and encountered the
same cause again. Do not count assistant retries, duplicated archives, quoted
history, restamped rollouts, synthetic evaluation prompts, or replayed prefixes.
Bind every accepted occurrence to stable root-task, opportunity, causal-cluster,
and source-event identities. Normalized text or a content fingerprint can support
duplicate detection, but cannot establish uniqueness by itself.

## Corpus And Causal Clustering

Inspect `~/.codex/sessions` and `~/.codex/archived_sessions` as one corpus through
`$codex-session-mining`. Include both dated and flat archived layouts when they
exist. Deduplicate cross-root copies and lifecycle replays by identity and
normalized content, while preserving later genuine human follow-ups.

Cluster evidence around the narrowest supported cause:

- Merge multiple symptoms from one causal episode into one occurrence.
- Do not let one symptom inflate several overlapping cases.
- Split cases only when they require independently reversible remedies.
- Record enough chronology to explain why separate occurrences are independent.

Exclude every historical Daily and Weekly Skill Friction run family, including
their direct and transitive descendants, replays, generated bookkeeping, automated
repair attempts, and reviewer-only prompts. A later explicit human correction can
open a separate `automation-derived` case, but it does not reinforce the case that
generated it.

## Candidate Strength

Assign exactly one support result independently of lifecycle status:

- `repeated`: the same supported cause appeared in distinct real opportunities.
- `novel`: one supported occurrence without sufficient recurrence.
- `no_issue`: the evidence does not support the suspected cause.

Do not create a case for `no_issue`. Stage a new `novel` case as `watching`; a
scheduled audit must not promote it solely from that one occurrence. Independent
recurrence may make a `repeated` case eligible for `proposed`, but does not select
or approve publication or repair.

Evaluate `high_signal` orthogonally and map it to the ledger urgency level
`high-signal` only when direct evidence satisfies at least one closed qualification
below:

1. data loss or corruption, or failure of a recovery boundary;
2. credential or private-data exposure, or unauthorized access;
3. an unauthorized irreversible external side effect; or
4. a demonstrated authority-boundary breach with material impact.

Bind the urgency reason to the schema's exact closed reason and to source-event
IDs already present in that case's evidence.

Awkward command shape, cost or latency, an ordinary failure, and one user
correction do not qualify. `high_signal` changes review priority only. It does not
automatically propose, publish, or repair a case, and it does not bypass Joey's
repair choice, the repo-first rule, or the global-scope gate. There is no numerical
cap on supported candidates or Joey-selected publication cases; report every
supported case without expanding dormant cases by default.

## Currentness

Evaluate each case against the current installed behavior before recommending it
for review or publication. Prefer a static inspection, exact configuration read,
or narrow no-side-effect probe. Record the observed version or artifact identity
when available.

An unrelated install, overlay release, or automation update does not reset the
case's evidence window and must not postpone an unresolved older event. Keep
`evidence_last_seen`, `lifecycle_changed_at`, and `currentness_checked_at` as
distinct clocks. A same-outcome check may update `currentness_checked_at`, but that
clock-only change must not change the semantic revision, publication eligibility,
or dormancy clock. Its timestamp, derived full-file digest, or occurrence in a
newer Daily snapshot cannot by itself invalidate a prior publication selection.

A change to the currentness outcome or applicability is semantic: update the
canonical semantic digest and increment the integer revision so a selection bound
to the prior meaning becomes `stale-selection`. If the problem is no longer
present, preserve the case and record the current reason; do not manufacture a
repair. Distinguish:

- issue absent in the current artifact;
- validation unavailable or unreadable;
- evidence contradicted;
- issue still reproducible.

## Repair Placement

Default to a repair in the repository that owns the affected workflow, skill,
script, or policy. Repeated manifestations inside one human root task demonstrate
persistence, not global breadth.

Use `cross-workflow` scope only when:

1. independent evidence spans at least two stable human root-task identities; and
2. it also spans at least two genuinely different workflows or repository roots,
   and the shared layer owns the cause.

One human root task never satisfies breadth, even if it crosses several
repositories or workflows. The only single-root global exception is a directly
demonstrated, narrow, repository-independent authorization or data-integrity
invariant that cannot be enforced safely at the owning repository. Seal it as a
`global-invariant` with the schema's exact invariant kind and an explicit
repository-independent rationale. This exception does not weaken any review or
approval gate. Prefer the smallest reversible placement.
