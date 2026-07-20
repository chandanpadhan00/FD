# ASNF Fraud Detection Framework — Reference Documentation

**System:** `asnf_fraud` schema (PostgreSQL) + `identity_ring_detector.py`
**Source data:** `asnfdm.pcd_phi_consolidated_vw` (read-only)
**Companion files:** [`fraud_rule_engine.sql`](fraud_rule_engine.sql), [`identity_ring_detector.py`](identity_ring_detector.py)

---

## 1. Purpose & Scope

### 1.1 What this system does

This is a **prioritization engine**, not a fraud-determination engine. It scans every case in `pcd_phi_consolidated_vw`, runs a set of independent detection rules against it, and produces a single ranked queue — `asnf_fraud.case_risk_score_latest` — ordered by a composite `fraud_risk_score`. The job it does is: *turn tens of thousands of cases into the fifty an investigator should look at first.*

It does **not**:
- Deny, approve, or hold any case automatically.
- Determine that fraud occurred. Every flag is a hypothesis for a human to verify.
- Replace clinical or eligibility review — it sits alongside those processes, reading the same data after the fact.

This distinction matters because a wrong flag has a real cost: a patient's aid under manual review while an investigator clears it. The scoring model (Section 5) is built specifically to resist over-triggering on a single weak signal.

### 1.2 What's in scope

Detection logic is organized around four "lenses" — four different ways fraud leaves a fingerprint in this data:

| Lens | What it looks for | Why |
|---|---|---|
| **Contradiction** | Two fields that should agree, but don't (e.g. `_reported` vs `_validated` pairs) | No single field is suspicious on its own — fraud shows up as disagreement between fields that should match |
| **Timeline** | Dates in an impossible or implausibly fast order | Legitimate cases move intake → verification → determination → ship in order, with realistic gaps |
| **Graph** | One identity element (email, phone, surname, office contact) shared across many distinct cases/patients/prescribers | Fraud rings fan out from a shared resource; the trick is counting the *right* entity, not just case volume |
| **Geography** | Patient, prescriber, and address relationships that don't make geographic sense | A patient's doctor and pharmacy should be roughly local; scatter is the anomaly |

17 rules currently implemented across these four lenses (Section 4).

### 1.3 What's explicitly out of scope (for now)

- **Policy/member-ID-level insurance matching** — the view has no policy/member ID field, so insurance-sharing detection is limited to payer+plan-name clustering, which is weaker evidence. Flagged as a data gap, not built.
- **Statistical distribution tests** (Benford's law on income digits, chi-square on FPL bunching) — these need a proper stats library, not SQL. Not yet built into the engine; would run as a separate offline analysis.
- **Automated weight calibration** (e.g. logistic regression against confirmed outcomes) — the `rule_precision` view (Section 6) provides the raw ingredients, but the actual reweighting is a manual/periodic exercise, not automated.
- **Any write-back to `asnfdm`** — this system only ever reads the source view. It cannot and does not modify case status, eligibility, or PHI/PCD records.

---

## 2. Architecture

### 2.1 Schema separation

Two schemas are involved:

- **`asnfdm`** — owned by the source data pipeline. Contains `pcd_phi_consolidated_vw`. This engine only ever `SELECT`s from it; it is never written to.
- **`asnf_fraud`** — owned entirely by this engine. Contains all rule metadata, thresholds, results, and scoring views. Safe to alter, rebuild, or drop without affecting the source data.

### 2.2 Two execution engines, one output contract

| | SQL engine | Python engine |
|---|---|---|
| Where | `asnf_fraud.detect_*()` functions, run via `asnf_fraud.run_all_rules()` | `identity_ring_detector.py` |
| Handles | Contradiction, timeline, most graph/geography rules — anything expressible as a single set-based query | Multi-hop identity-ring detection (graph connected components) — patterns that need transitive linking across multiple shared fields, which SQL self-joins handle poorly |
| Writes to | `asnf_fraud.flags` | `asnf_fraud.flags` (same table) |
| Rule IDs owned | CON01–05, TML01–05, GRF01–04, GEO01–02 | GRF05 |

Both engines write into the **same** `asnf_fraud.flags` table under a **shared `run_id`**, so a single run of `python identity_ring_detector.py` (which calls the SQL engine first, then runs its own detector under the same `run_id`) produces one combined, cross-engine risk score per case.

### 2.3 Why a `rule_registry.implementation` column exists

`run_all_rules()` loops over every *active* row in `rule_registry` and tries to call a matching `detect_<rule_id>()` SQL function. `GRF05` has no such function — it's written directly by the Python script. The `implementation` column (`'sql'` or `'python'`) tells the orchestrator which rules it actually owns, so it only dispatches to `implementation = 'sql'` rows. This was a real bug hit during deployment (`function asnf_fraud.detect_grf05() does not exist`) and is now fixed at the schema level.

---

## 3. Core Design Principles

1. **One rule = one detector.** Every SQL rule is a single, isolated function (`detect_<rule_id>()`) or, for `GRF05`, a single Python function. No detector calls another. Any rule can be added, disabled, or retuned without understanding the other sixteen.
2. **Uniform output.** Every detector — SQL or Python — returns exactly the same shape: `(case_id, patient_id, rule_id, points, evidence)`. `evidence` is JSON containing the actual field values that tripped the rule, not just a boolean.
3. **Thresholds are config, not code.** Every number a rule depends on (`> 5`, `<= 2 days`, `min_ring_size`, etc.) lives in `asnf_fraud.rule_config` as a `(rule_id, param_name, param_value)` row. Retuning a threshold is an `UPDATE` statement, not a deploy.
4. **The orchestrator never changes.** Adding rule #18 means: write `detect_r018()` (or a Python equivalent), insert one `rule_registry` row and its `rule_config` rows. `run_all_rules()`, `case_risk_score`, and `rule_precision` all pick it up automatically because they query the registry/config tables, not a hardcoded list.

---

## 4. Rule Catalog

Points and thresholds below are the values currently seeded in `rule_config` — all changeable via `UPDATE`, none require touching a detector.

### 4.1 Contradiction lens — `_reported` vs `_validated` disagreement

| Rule | Trigger | Points | Config |
|---|---|---|---|
| **CON01** | `patient_income_validated` exceeds `patient_income_reported` by more than a configured percentage. (`patient_income_reported` is stored as text in the source view and occasionally has stray formatting — passed through `safe_numeric()` first, which strips non-numeric characters and returns `NULL` on anything uncastable rather than failing the query.) | 10 | `delta_pct = 0.25` (25% understatement) |
| **CON02** | `patient_fpl_validated` exceeds `patient_fpl_reported` by more than a configured point spread. | 8 | `delta_points = 15` |
| **CON03** | Reported household size exceeds validated household size by the configured minimum (inflating the FPL denominator lowers the calculated FPL%, making the patient look poorer). Same `safe_numeric()` handling as CON01. | 8 | `min_diff = 1` |
| **CON04** | `overnetworth` flag says the patient is under the net-worth limit (`'N'`/`'FALSE'`/`'0'`), but `patient_net_worth_reported` exceeds the configured ceiling anyway — a direct contradiction between the flag and the underlying figure. | 8 | `net_worth_limit = 1,000,000` *(placeholder — set to the actual program ceiling before relying on this rule)* |
| **CON05** | Patient has an active primary insurance payer on file, but it was explicitly excluded from the eligibility determination (`pri_medical_insurance_used_for_determination = 'N'`), and the case was still approved. | 15 | — |

### 4.2 Timeline lens — impossible or implausibly fast sequencing

| Rule | Trigger | Points | Config |
|---|---|---|---|
| **TML01** | `case_determination_date` falls *before* `file_receipt_date_time` — a physically impossible ordering (you can't determine a case before you received the file). Highest weight in the engine because this cannot be a false positive; if it fires, the data is wrong. | 30 | — |
| **TML02** | `last_ship_date` falls outside the `eligibility_start_date`–`eligibility_end_date` window — drug shipped before eligibility began or after it lapsed. | 15 | — |
| **TML03** | Days between `file_receipt_date_time` and `last_ship_date` is at or below a configured minimum — too fast for real verification to plausibly have happened. | 12 | `max_days = 2` |
| **TML04** | "Denial-shopping": a patient's case was created within a configured number of days of their *own* prior case being denied/rejected. Uses `LAG()` windowed by `patient_id`, ordered by `case_created_date`. | 10 | `max_days = 14` |
| **TML05** | "Case churn": multiple distinct `case_id`s opened under the same `hub_case_id` within a configured window — rapid re-casing that may be working around per-case quantity limits. *(Adapted from an original "sub_case_id" design — that column doesn't exist in the real view; `hub_case_id` grouping captures the same intent.)* | 10 | `min_subcases = 3`, `window_days = 30` |

### 4.3 Graph lens — shared identity elements fanning out

| Rule | Trigger | Points | Config |
|---|---|---|---|
| **GRF01** | One `email_addr` shared across a configured minimum number of distinct `patient_id`s. | 12 | `min_patients = 4` |
| **GRF02** | One office contact name (`office_contact_first_name` + `office_contact_last_name`) shared across a configured minimum number of distinct `md_npi` prescribers — a shared front-desk "identity" spanning unrelated providers. | 10 | `min_prescribers = 4` |
| **GRF03** | One address (`addr1` + `addr_zip`) shared by a configured minimum number of **distinct surnames**. Deliberately counts a different entity than GRF04 using the identical query shape — this is the "count the right entity" version of the address rule. | 18 | `min_surnames = 3` |
| **GRF04** | *Legacy baseline*: one address shared across a configured minimum number of distinct `case_id`s, scoped to `drug`. This is the original baseline rule from before this framework existed — kept for continuity, deliberately low-weighted because it's the weakest signal in the engine (surname-fanout on the same address, GRF03, is much sharper). | 5 | `min_cases = 6` |
| **GRF05** *(Python)* | Multi-hop identity ring: builds a graph where nodes are patients and edges are (a) shared `email_addr`/`phone_preferred`/`phone_alternate` (any cross-combination) or (b) a fuzzy `lname`+`fname` match on patients with an identical `dob` (blocked on `dob` to keep the comparison tractable; Levenshtein distance on surname, fuzzy ratio on first name). Flags every connected component (ring) at or above a configured minimum size — this catches rings where A links to B via phone and B links to C via email, even though A and C share nothing directly, which no single-field `GROUP BY` can see. | 20 | `min_ring_size = 3`, `max_lname_distance = 2`, `min_fname_similarity = 85` |

### 4.4 Geography lens — implausible distance between related parties

| Rule | Trigger | Points | Config |
|---|---|---|---|
| **GEO01** | A prescriber's state (`md_state`) differs from the patient's state (`patient_state`) for a configured minimum number of cases from that same prescriber — a diffuse legitimate telehealth practice looks different from one out-of-state cluster repeating. | 12 | `min_cases = 6` |
| **GEO02** | Patient address matches a configured pipe-delimited list of institutional/correctional keywords (`CORRECTION`, `PRISON`, `DETENTION`, `FCI`, `USP`, `COUNTY JAIL`, `DOC`, `STATE PEN`, `REHABILITATION CTR`). The pattern list is a config value, not hardcoded — adding a new keyword is an `UPDATE`, not a deploy. | 25 | `patterns = 'CORRECTION\|PRISON\|DETENTION\|...'` |

---

## 5. Scoring Methodology

### 5.1 Raw score

For a given `run_id`, every flag a case received is summed by points:

```
raw_score = SUM(points) across all flags for that case_id in that run
```

### 5.2 Cross-lens corroboration multiplier

A case flagged by five rules that are all really "the same signal" (e.g. five graph rules all firing off the same shared address) is weaker evidence than a case flagged by three *independent* lenses agreeing — a timeline break, a contradiction, and a graph fan-out are unlikely to all be coincidental. The engine rewards that independence explicitly:

```
distinct_lenses_triggered = COUNT(DISTINCT lens) across the case's flags   -- max 4
multiplier = 1 + 0.15 × MAX(distinct_lenses_triggered − 1, 0)
fraud_risk_score = LEAST(100, raw_score × multiplier)
```

| Distinct lenses triggered | Multiplier |
|---|---|
| 1 | 1.00× |
| 2 | 1.15× |
| 3 | 1.30× |
| 4 | 1.45× |

`distinct_rules_triggered` is tracked separately and is *not* part of the multiplier — firing more rules within the same lens doesn't escalate the way corroboration across lenses does.

### 5.3 Risk tiers

| `fraud_risk_score` | Tier | Suggested action |
|---|---|---|
| ≥ 75 | **CRITICAL** | Same-day manual audit hold |
| 50–74 | **HIGH** | Audit queue within 48h |
| 25–49 | **MEDIUM** | Batch-reviewed weekly |
| < 25 | **LOW** | Monitored, no action |

### 5.4 Worked examples

**Case A** — flagged by `TML01` (30 pts, timeline) + `CON01` (10 pts, contradiction) + `GRF03` (18 pts, graph):
```
raw_score = 30 + 10 + 18 = 58
distinct_lenses_triggered = 3  (timeline, contradiction, graph)
multiplier = 1 + 0.15 × 2 = 1.30
fraud_risk_score = MIN(100, 58 × 1.30) = 75.4  →  CRITICAL
```
Three independent lenses pushed a 58-point raw score over the CRITICAL line.

**Case B** — flagged by `GEO02` only (25 pts, geography):
```
raw_score = 25, distinct_lenses_triggered = 1, multiplier = 1.00
fraud_risk_score = 25  →  MEDIUM (boundary)
```

**Case C** — flagged by `GEO02` (25, geography) + `CON05` (15, contradiction):
```
raw_score = 40, distinct_lenses_triggered = 2, multiplier = 1.15
fraud_risk_score = 46  →  still MEDIUM, but meaningfully closer to HIGH than Case B despite only 15 more raw points — the second independent lens did real work.
```

**Case D** — flagged by `GRF04` alone (5 pts, graph — the weak legacy baseline):
```
raw_score = 5, multiplier = 1.00, fraud_risk_score = 5  →  LOW
```
Confirms the legacy address-clustering rule alone is intentionally not enough to surface a case on its own.

---

## 6. Feedback Loop & Retuning

### 6.1 Recording outcomes

After an investigator reviews a flagged case, the outcome is written to `asnf_fraud.audit_outcomes`:

```sql
INSERT INTO asnf_fraud.audit_outcomes (case_id, outcome, audited_by, notes)
VALUES ('CASE123', 'CONFIRMED_FRAUD', 'investigator_name', '...');
-- outcome: CONFIRMED_FRAUD | FALSE_POSITIVE | INCONCLUSIVE
```

### 6.2 Measuring rule quality

```sql
SELECT * FROM asnf_fraud.rule_precision;
```

This joins `flags` to `audit_outcomes` per `rule_id` and computes:
```
precision = CONFIRMED_FRAUD count / (CONFIRMED_FRAUD + FALSE_POSITIVE count)
```
per rule. This is what turns "which rules fire a lot" into "which rules actually catch fraud" — a rule with high volume and low precision is a candidate for reweighting down or deactivating; a rule with low volume and high precision might be underweighted.

### 6.3 Retuning without a deploy

```sql
-- Change a threshold
UPDATE asnf_fraud.rule_config SET param_value = '0.20'
WHERE rule_id = 'CON01' AND param_name = 'delta_pct';

-- Change a rule's weight
UPDATE asnf_fraud.rule_config SET param_value = '5'
WHERE rule_id = 'GRF04' AND param_name = 'points';

-- Disable a noisy rule entirely
UPDATE asnf_fraud.rule_registry SET active = false WHERE rule_id = 'GRF04';
```
None of these require editing a detector function, redeploying the SQL file, or touching Python.

---

## 7. Operational Workflow

```sql
-- 1. Run every active SQL rule + the Python identity-ring detector under one run_id
--    (from the shell, not SQL):
--       python identity_ring_detector.py

-- 2. Review the prioritized queue for the most recent run
SELECT * FROM asnf_fraud.case_risk_score_latest
ORDER BY fraud_risk_score DESC;

-- 3. Drill into one case's full evidence trail
SELECT evidence_trail FROM asnf_fraud.case_risk_score_latest
WHERE case_id = 'CASE123';

-- 4. After investigation, log the outcome
INSERT INTO asnf_fraud.audit_outcomes (case_id, outcome, audited_by, notes)
VALUES ('CASE123', 'CONFIRMED_FRAUD', 'investigator_name', 'notes here');

-- 5. Periodically, check rule quality and retune
SELECT * FROM asnf_fraud.rule_precision;
```

`identity_ring_detector.py` can also be run with `--skip-sql` (Python detector only, new `run_id`) or `--run-id <uuid>` (attach to an existing run) — see the script's `argparse` help.

---

## 8. Known Assumptions & Limitations

- **`pcd_phi_consolidated_vw` is assumed already deduplicated/QC-clean** — confirmed with the business that `is_latest`/`qc_passed` filtering is unnecessary because the view only exposes current, QC-passed rows. If that assumption changes, both engines need a filter added.
- **`CON04`'s `net_worth_limit` (currently 1,000,000) is a placeholder** — must be set to the actual program net-worth ceiling before this rule is trusted.
- **`GEO02`'s institutional keyword list is pattern-matching, not a reference join** — a maintained table of known correctional-facility addresses (e.g. from public BOP/state DOC data) would be materially more precise than string matching, and is a natural next improvement.
- **`TML05` is based on `hub_case_id`**, substituted for an original design that assumed a `sub_case_id` column which does not exist in the real view. The substitution captures the same "rapid re-casing" intent but hasn't been validated against confirmed fraud cases yet.
- **Insurance-sharing detection is limited by the absence of a policy/member ID field** in the source view — payer+plan-name clustering (not currently implemented as a standalone rule) would be considerably weaker evidence than true policy-number matching.
- **No automated weight recalibration yet** — `rule_precision` provides the precision-per-rule input, but translating that into revised `rule_config` weights is a manual periodic exercise, not a scheduled job.
