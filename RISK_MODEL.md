# Risk model

`deprisk` ranks the packages in a `requirements.txt` by how risky they are to depend on, for
CPython 3.12 on Linux x86_64 (glibc 2.36). It uses only PyPI JSON metadata. Every score is
relative to a frozen baseline of the 5,000 most downloaded PyPI projects. The score is a
deterministic, explainable ranking index: it is **not** a probability of failure, and
"unusual" is not the same as "unsafe".

## Baseline

- **Population:** the first 5,000 rows of the top-pypi-packages list (`last_update`
  2026-11-01 06:41:05), fetched into a compact snapshot (`data/snapshot.json.gz`, id
  `5c1e0e851f88d945`).
- **Reference time `T`:** the latest fetch time of any response the snapshot was built from
  (2026-11-25T13:50:06Z). Scoring is a pure function of the snapshot, `T` and the
  configuration, so it is reproduced exactly offline (tested with network access blocked).
- **Exclusions:** 80 of 5,000 projects cannot be scored and are counted by reason: 77
  publish only pre-releases, 2 have only yanked files, 1 is no longer on PyPI.
  **n = 4,920.**
- **Placement:** every baseline package gets the same signals as the targets, with an empty
  version specifier. The 40 targets are in the top 5,000. They are scored with their own
  requirement specifiers, against the same distributions.

## Signals

| Category | Signal | Measured on | Riskier when |
|---|---|---|---|
| Maintenance | S1 days since the last non-yanked upload (any version) | whole project | higher |
| Maintenance | S2 final releases in the 24 months before `T` | whole project | lower |
| Compatibility | S4 Python 3.12 evidence (ordinal state 0–5) | reference version | worse state |
| Compatibility | S5 install path: wheel / sdist only / none | effective version | worse state |
| Security | S6 distinct vulnerabilities (deduplicated advisories) | reference version | higher |
| Dependencies | S7 direct runtime dependencies on the target environment | reference version | higher |

The **effective version** is the highest final release that the specifier allows and that
has an installable file for the target. A file is installable if it is not yanked, its
`requires_python` admits 3.12, and it is either a wheel with an accepted tag or an sdist.
The **reference version** is the effective version, or, if there is none, the newest final
release that has a non-yanked file.

Evidence-only signals are shown in the report and to the agent, but never scored:

- S3: age of the effective version.
- S8: PyPI role accounts.
- S9: share of fully yanked releases.
- S10: 0.x version.
- S14: "Inactive" development status.

### S4 states (first matching rule)

| State | Meaning |
|---|---|
| 5 | no effective version |
| 4 | a newer release in the specifier exists but is not installable on 3.12, so pip falls back to an older one |
| 0 | a `Python :: 3.N` classifier with N ≥ 12, or an eligible cp312 wheel |
| 1 | an eligible file declares `requires_python` (admits 3.12, no positive evidence) |
| 3 | only stale `Python :: 3.N` classifiers (N < 12) |
| 2 | no declaration and no Python 3 minor classifiers |

### S6: counting vulnerabilities, not advisory entries

PyPI's `vulnerabilities` field often lists one vulnerability several times, under different
advisory databases. For example, pycrypto 2.6.1 has 4 entries for 2 CVEs: each CVE appears
as a `PYSEC-…` entry and as a `GHSA-…` entry, and each entry names the other as an alias.
Counting entries would double such packages.

S6 therefore groups the non-withdrawn entries. Two entries describe the same vulnerability
when their identifier sets (`id` plus `aliases`) share a value. Links are transitive: if A
and B share an id, and B and C share another, then A, B and C are one vulnerability. S6 is
the number of groups.

- **Malformed entries:** an entry stored as `id: "unknown"` with no aliases cannot be linked,
  so it counts on its own (the cautious reading).
- **Evidence:** the original entries stay in the evidence next to the groups.
- **Flags:** a vulnerability "has a fix" when any of its entries lists `fixed_in` versions.

Effect on this run: 8 of the 11 baseline packages with advisories listed every vulnerability
exactly twice; the other 3 had a single entry. The duplicated counts halved, and their order relative to each other did
not change. Every contribution, total, final score and rank is therefore identical before and
after deduplication. Only the raw S6 values and the flag evidence changed (pycrypto: 4 → 2).

## Combining the signals

For a value `x` of signal `s`, let `k` be the number of baseline packages whose value is at
least as risky. The direction comes from the table above, and ties count as at least as
risky. Then:

- `q = max(k, 1) / n_s`, the share of the baseline that is as risky or riskier.
- The contribution is `−ln q`. The most common best value contributes 0. The maximum is
  `ln n_s` ≈ 8.5.
- A value riskier than every baseline value is floored at `q = 1/n_s` and flagged
  `beyond_baseline_range`.
- Category score = the mean of its signals' contributions, so correlated signals within a
  category count as one construct. Total = the sum of the four categories.
- Final score = 100 × the share of baseline totals strictly below the package's total, so a
  score of X means "riskier than X% of the top 5,000".
- Ranking: final score, then total, then name. All values are rounded to 6 decimals before
  they are compared.

The `−ln` transform is borrowed from Fisher's method for combining p-values. It makes a rare
bad value add a lot instead of being averaged away. It measures rarity, not severity, which
is why critical flags (unfixed advisories, no installable version, a pip fallback, sdist
only, missing metadata) are shown next to the score. Flags never change the score.

## Missing metadata

Missing information is never treated as evidence of safety, and no signal is ever dropped.

| Case | Handling |
|---|---|
| `requires_dist` is `null` or absent | S7 unknown: neutral `q = 0.5` (contribution ln 2 ≈ 0.69), flag `missing:requires_dist` |
| `requires_dist` is `[]`, or every entry is excluded by markers or extras | S7 = 0 |
| a `requires_dist` entry is malformed | counted as a dependency; S7 is a lower bound and is never placed below neutral |
| `vulnerabilities` is `null` or absent | S6 unknown: neutral `q = 0.5`, flag `missing:vulnerabilities` |
| `vulnerabilities` is `[]` | S6 = 0 (PyPI's explicit answer, within OSV's coverage) |

Unknown values are left out of the baseline distribution of that signal (`n_s`), and baseline
packages with an unknown value receive the same neutral contribution in their own totals.

### The observed `requires_dist: null` rate and what it means

In this snapshot, `requires_dist` is `null` for **1,142 of 4,920 baseline packages (23%)**
and for **15 of the 40 targets**, among them numpy, click, pyyaml and six. PyPI commonly
returns `null` when a release declares no dependencies. It also returns `null` when
dependencies were not recorded in the uploaded metadata. The two cases look identical, so
the model does not guess:

- Such a package receives ln 2 ≈ 0.69 in the dependencies category, instead of 0 for a
  declared empty list. That is about 40% of the median baseline total (1.74); the 90th
  percentile total is 3.97.
- A dependency-free package with `null` therefore ranks somewhat higher than an identical
  one with an explicit `[]`. The `missing:requires_dist` flag makes that visible in the
  report.
- The S7 distribution is built from the 3,778 packages that declare a value. Packages with
  many declared dependencies are compared only with other declared values.
- This penalty is a deliberate consequence of "missing is never safe". It does not reward a
  project for declaring nothing.

## Differences from pip

The version rules describe what the metadata allows pip to install. They are not proof that
a package builds or works. Where the rules differ from pip, they refuse to assume
installability that the metadata does not show:

1. **Only pre-releases:** such a project is unscored ("only pre-releases"), whereas pip
   installs a pre-release when no final release exists. This affects 77 baseline projects,
   mostly SDK betas. None of the 40 targets is affected.
2. **Invalid `requires_python`:** a value that is not a valid specifier is treated as not
   admitting 3.12. pip ignores an invalid value and installs the file.
3. **Legacy formats:** eggs and other legacy formats are never installable. Modern pip
   does not install them either.
4. **Patch-level bounds:** `requires_python` is checked against 3.12.0 only.
5. **Wheel tags:** accepted tags are a fixed list (cp312 / abi3 / py3 on manylinux 2.5–2.36
   x86_64, and `any`), not the tags of the machine running the tool. musllinux wheels are
   not accepted.

## Modelling choices and limitations

These are judgements, not values derived from data:

- which signals are scored, and how they are grouped into categories;
- the ordinal states and their order (S4 state 2 vs 3 in particular);
- the mean within a category, and equal weight for every category;
- the `−ln` transform and the `q` floor;
- the neutral value for missing data;
- the 24-month S2 window.

Other limitations:

- The signals are not independent.
- The popular-package baseline is not a "safe" baseline.
- PyPI advisory data inherits OSV's coverage gaps.
- There is no build, runtime or transitive-dependency verification. Results assume a fresh
  install.
