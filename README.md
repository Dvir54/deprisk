# deprisk: which of my dependencies will ruin my weekend?

`deprisk` ranks the packages in a `requirements.txt` by how risky they are to depend on, for a
service running CPython 3.12 on Linux x86_64. It uses only PyPI JSON metadata, and every score is
relative to a frozen baseline of the 5,000 most downloaded PyPI projects. A tool-calling Claude
agent then recommends one concrete action (upgrade, pin, replace, do nothing) for each of the
10 riskiest packages, and code checks every fact the agent cites before the recommendation is
accepted.

## Submission contents

| Deliverable | Where |
|---|---|
| The code and how to run it | [`deprisk/`](deprisk), [`tests/`](tests), this README |
| Output for the attached `requirements.txt` | [`output/REPORT.md`](output/REPORT.md): the 40 ranked packages with score and main risk factors, and the top-10 recommendations. [`output/results.json`](output/results.json): every signal value, placement, flag and the agent's tool-call log |
| The risk model: signals, why, how they combine, assumptions | [`docs/RISK_MODEL.md`](docs/RISK_MODEL.md) |
| How the top-5,000 baseline is used: what was measured, how each of the 40 is placed | [`docs/RISK_MODEL.md`](docs/RISK_MODEL.md), sections "Baseline", "What was measured across the baseline" and "Worked example" |
| `HOW_I_BUILT_IT.md` | [`docs/HOW_I_BUILT_IT.md`](docs/HOW_I_BUILT_IT.md) |
| Input | [`assignment/requirements.txt`](assignment/requirements.txt) |
| Frozen baseline data (reproduces every score offline) | [`data/snapshot.json.gz`](data/snapshot.json.gz) |

## Setup

Requires [`uv`](https://docs.astral.sh/uv/). It installs Python 3.12 and the pinned
dependencies (`anthropic`, `httpx`, `packaging`, `pydantic`; dev: `pytest`, `ruff`):

```
uv python install 3.12
uv sync
```

## Reproduce the scores offline (no API key, no network)

The baseline is committed as a compact snapshot (`data/snapshot.json.gz`, 23.6 MB). Scoring is
a pure function of the snapshot, its reference time `T` and the configuration, so this
reproduces every score and rank in `output/results.json` exactly:

```
uv run python -m deprisk analyze --no-llm --out output/offline
```

`tests/test_offline_reproducibility.py` checks this with network access blocked. The agent's
recommendations are recorded in `output/`, not reproduced: LLM output is not deterministic.

## Full run with the agent

The agent uses the Anthropic API. Set `ANTHROPIC_API_KEY`, check access, then run:

```
uv run python -m deprisk check-llm
uv run python -m deprisk analyze
```

This scores the 40 packages in `assignment/requirements.txt` and writes `output/results.json`
and `output/REPORT.md`. The default model is Claude Sonnet 5.5 at effort `medium`; override
with `DEPRISK_LLM_MODEL` and `DEPRISK_LLM_EFFORT` (`low`, `medium`, `high`, `xhigh`, `max`). The
submitted run made 23 requests in under 2 minutes and cost about US$0.23. Replacement candidates that are
not in the snapshot are read live from PyPI (cached under `.cache/pypi/`).

Options: `analyze [REQUIREMENTS] [--snapshot PATH] [--out DIR] [--no-llm] [--top-n K]`;
`-v` before the command enables debug logging.

## Refresh the baseline (network)

```
uv run python -m deprisk fetch
uv run python -m deprisk snapshot --requirements assignment/requirements.txt
```

`fetch` downloads the top-packages list and the 5,000 project JSON documents into
`.cache/pypi/` (resumable; about 5 minutes, about 280 MB). `snapshot` extracts the compact
records, fetches the version endpoints that the reference versions need, and writes
`data/snapshot.json.gz` with a new `T`. A rebuilt snapshot gives new scores, since PyPI has
moved on.

For a quick end-to-end check on a small baseline (300 evenly spaced ranks plus the targets):

```
uv run python -m deprisk snapshot --sample 300 --requirements tests/smoke/requirements-smoke.txt --include-targets --out data/smoke/snapshot.json.gz
uv run python -m deprisk analyze tests/smoke/requirements-smoke.txt --snapshot data/smoke/snapshot.json.gz --out output/smoke --top-n 2
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | every package scored, every recommendation validated |
| 1 | invalid run: a package could not be scored, or a recommendation stayed unresolved after 3 attempts (outputs are still written and list why) |
| 2 | usage, configuration or credential error, or a required data source or snapshot is missing |

## How it works

1. **Phase A, snapshot (network):** top-5,000 list → PyPI project JSON → compact records with
   only the fields scoring needs (no free text, no raw responses).
2. **Phase B, scoring (offline, deterministic):** for each package, the version pip would
   install on 3.12 is resolved from the metadata; six signals are computed (maintenance,
   Python 3.12 compatibility, install path, known vulnerabilities, dependency count) and each
   is placed on the baseline's distribution of the same signal. Rare risky values add more:
   each signal contributes `−ln q`, where `q` is the share of the baseline that is as risky or
   riskier. Critical flags (unfixed advisory, no installable version, pip fallback, sdist
   only, missing metadata) are shown next to the score but never change it. Details in
   [`docs/RISK_MODEL.md`](docs/RISK_MODEL.md).
3. **Phase C, agent (network):** for each of the top 10, Claude gets the deterministic profile
   and six read-only tools (profile, release history, version details, eligible versions,
   requirement context, replacement lookup scored against the same frozen baseline). It
   submits one action with a finding and evidence that cites logged tool outputs by call id
   and field. A pure validator checks the facts: the version exists, is not yanked and is
   installable; an upgrade really raises the floor and leaves the cited advisory behind; a
   replacement exists and scores lower; the evidence matches the log. A rejected submission
   goes back to the agent with the errors (up to 3 attempts). Recommendations are labelled
   "facts validated; suitability not verified": the cited facts are checked, while the
   rationale text and whether a replacement fits the service's code are the agent's own.

## Project layout

```
deprisk/
  config.py      every tunable constant
  cli.py         commands and exit codes
  pipeline.py    phase orchestration and file IO
  data/          PyPI client and cache, compact records, snapshot, requirements parser
  risk/          versions and target environment, signals, scoring, flags, baseline, analysis
  agent/         tools, validator, prompts, tool-use loop (the only module importing anthropic)
  reporting/     results.json and REPORT.md
tests/           mirrors deprisk/; uv run pytest -q
```

Development: `uv run pytest -q` (about 300 tests, under a minute) and
`uv run ruff format deprisk tests && uv run ruff check deprisk tests`.

## Limitations

The score is a relative ranking index, not a probability of failure. It reads metadata only:
no build, runtime or transitive-dependency checks, a fresh install is assumed, and advisory
data inherits OSV's coverage gaps. `requires_dist: null` (23% of the baseline) is scored as
unknown rather than as zero dependencies. The agent's recommendations are factually checked
but not tested against the service's code. See [`docs/RISK_MODEL.md`](docs/RISK_MODEL.md) for the full
list.
