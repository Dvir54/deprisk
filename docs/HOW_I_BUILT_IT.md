# How I built it

I built `deprisk` with AI assistance (mainly Claude Code) in stages, with my approval required
before each stage moved on: research, a written specification, technical review, an
implementation plan, and implementation milestone by milestone, with tests written first and a
report plus my approval before every commit.

## What I delegated to AI

- **Research:** reading the assignment, probing the PyPI JSON API and the top-packages list
  (read-only), and writing up what the metadata can and cannot show.
- **Specification and planning:** first drafts of the specification and the implementation
  plan, including the module layout, interfaces, milestones and the test list per acceptance
  criterion.
- **Technical reviews:** reviewing drafts against the assignment and finding gaps, which I
  then decided whether to act on.
- **Coding and testing:** nearly all of the code and its tests: the PyPI client and cache,
  the snapshot, version and eligibility logic, signals, scoring, flags, baseline, reports,
  the agent's tools, the validator and the tool-use loop.
- **Running and checking:** the baseline download, the snapshot build, scans of all cached
  projects for edge cases, the smoke runs and the final run.
- **Documentation:** first drafts of the README, the risk-model description and this file.

## What I kept for myself

- **Requirements and scope:** what the tool must do, the acceptance criteria, what was left
  out, and when a stage was finished.
- **System design:** the split between a deterministic pipeline and an agent (below), and the
  architectural choices I approved or rejected along the way, such as the package layout
  with enforced import boundaries and a validator that never touches the network.
- **Engineering decisions:** the LLM (Claude Sonnet 5.5 at effort `medium`, configurable),
  no automatic fallback to another model when a request is refused, pydantic data models,
  a smoke test that must pass on a small baseline that includes the tested packages, and a
  hard cap on LLM requests per package.
- **Risk-model decisions made on real data:** counting distinct vulnerabilities instead of
  advisory entries (PyPI lists one CVE under several databases), treating
  `requires_dist: null` as unknown and documenting its 23% rate, and keeping the
  version-eligibility rules while documenting how they differ from pip.
- **Review and approval:** I read the proposals, challenged the ones I disagreed with, and
  approved every stage, every commit and the final submission.

## The risk model in short

Six signals in four categories (maintenance S1/S2, Python 3.12 compatibility S4/S5, known
vulnerabilities S6, direct dependencies S7), computed the same way for the 4,920 scorable
packages of the top-5,000 baseline and for the 40 targets. Each value is placed on the
baseline's distribution: `q` is the share of the baseline that is as risky or riskier, the
contribution is `−ln q`, categories are averaged and summed, and the final score is the share
of baseline totals below the package's total. The main assumptions are the choice of signals
and categories, equal weight per category, the ordinal states, a neutral value for missing
metadata (never treated as safe), metadata eligibility rather than real builds, and a fresh
install. Details and numbers: [`RISK_MODEL.md`](RISK_MODEL.md).

## One thing the AI got wrong that I caught

In the initial design phase the AI suggested building the whole solution as an agentic
system. Reading the assignment again, I challenged that: the risk score has to be
deterministic, reproducible and explainable per package, and an LLM in the scoring path would
undermine all three. I split the system in two:

- a **deterministic pipeline** for data collection, the baseline, risk calculation and
  ranking, which runs offline from a committed snapshot and is reproduced exactly by a test;
- an **agent** that investigates only the ten highest-risk packages, gathers evidence through
  read-only tools and recommends one action, with code checking every fact it cites.

The scores stayed reproducible and independently testable, and the agent is used where
judgement adds something: choosing which evidence to inspect and what to do about a package.
The lesson I took from it: not every part of an AI-powered system should be agentic. AI
belongs where it adds value, not everywhere it could be used.
