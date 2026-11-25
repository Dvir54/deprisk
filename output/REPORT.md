# Dependency risk report

## Summary

- **Target environment:** CPython 3.12 on Linux x86_64 (glibc 2.36, manylinux wheels), fresh install.
- **Baseline:** top 5000 PyPI projects by downloads (hugovk top-pypi-packages); list dated 2026-11-01; 4,920 scorable packages (excluded: data unavailable: 1, only pre-releases: 77, only yanked files: 2).
- **Analyzed:** 40 packages analyzed, 40 scored. Snapshot `5c1e0e851f88d945`, reference time T = 2026-11-25 13:50 UTC.

**Risk score:** a score of X means the package's combined risk is higher than X% of the baseline packages. Each signal (maintenance, Python 3.12 compatibility, known vulnerabilities, dependencies) adds more the rarer its value is in the baseline. It is a relative ranking, not a probability of failure. Method: `RISK_MODEL.md`; every signal value, placement and flag: `results.json`.

Signal ids used in the agent's rationales: S1 days since the last upload; S2 final releases in the last 24 months; S4 Python 3.12 evidence state; S5 install path state; S6 known vulnerabilities; S7 direct dependencies.

## Dependency ranking

| Rank | Package | Effective version | Risk score | Main risk factors |
|---:|---|---|---:|---|
| 1 | pycrypto | 2.6.1 | 99.96 | 2 known vulnerabilities (no fix listed); last upload 12.4 years ago; sdist only (built from source at install) |
| 2 | typing | 3.7.4.3 | 99.29 | pip falls back to the old release 3.7.4.3; sdist only (built from source at install); last upload 5.6 years ago |
| 3 | futures | 3.0.5 | 99.11 | pip falls back to the old release 3.0.5; sdist only (built from source at install); last upload 4.1 years ago |
| 4 | nose | 1.3.7 | 96.34 | last upload 11.5 years ago; no Python version metadata; no release in 2 years |
| 5 | enum34 | 1.1.10 | 93.54 | last upload 6.7 years ago; classifiers only for Python 3 versions before 3.12; no release in 2 years |
| 6 | pathlib | 1.0.1 | 90.81 | classifiers only for Python 3 versions before 3.12; last upload 4.6 years ago; no release in 2 years |
| 7 | flask | 3.1.3 | 81.36 | 6 direct dependencies; last upload 279 days ago; Python 3.12 support not confirmed (only requires_python) |
| 8 | celery | 5.7.0 | 77.09 | 9 direct dependencies |
| 9 | six | 1.17.0 | 72.97 | last upload 2.0 years ago; 1 release in 2 years; Python 3.12 support not confirmed (only requires_python) |
| 10 | aiohttp | 3.14.5 | 72.34 | 8 direct dependencies |
| 11 | httpx | 0.28.1 | 57.93 | 4 direct dependencies; 2 releases in 2 years; last upload 86 days ago |
| 12 | jinja2 | 3.1.6 | 55.75 | last upload 1.7 years ago; 2 releases in 2 years; Python 3.12 support not confirmed (only requires_python) |
| 13 | requests | 2.34.2 | 53.88 | 4 direct dependencies; last upload 195 days ago |
| 14 | arrow | 1.4.0 | 50.43 | last upload 1.1 years ago; 1 release in 2 years |
| 15 | retrying | 1.4.2 | 49.27 | last upload 1.3 years ago; 4 releases in 2 years |
| 16 | beautifulsoup4 | 4.15.0 | 45.22 | Python 3.12 support not confirmed (only requires_python); last upload 171 days ago |
| 17 | click | 8.5.1 | 40.10 | Python 3.12 support not confirmed (only requires_python) |
| 18 | psycopg2-binary | 2.9.13 | 38.60 | 3 releases in 2 years |
| 19 | mock | 5.2.0 | 36.10 | last upload 1.7 years ago; 1 release in 2 years |
| 20 | pydantic | 2.14.4 | 30.30 | 4 direct dependencies |
| 21 | pyyaml | 6.0.4 | 29.94 | 2 releases in 2 years |
| 22 | pendulum | 3.3.0 | 27.70 | 3 releases in 2 years |
| 23 | alembic | 1.20.1 | 26.18 | 3 direct dependencies |
| 24 | pytz | 2026.6 | 24.67 | no signal riskier than the baseline middle |
| 25 | simplejson | 4.3.0 | 23.07 | no signal riskier than the baseline middle |
| 26 | marshmallow | 4.4.0 | 19.74 | no signal riskier than the baseline middle |
| 27 | numpy | 2.5.5 | 17.09 | no signal riskier than the baseline middle |
| 28 | python-dateutil | 4.0.0 | 16.30 | 2 releases in 2 years |
| 29 | pandas | 3.1.1 | 16.02 | no signal riskier than the baseline middle |
| 30 | boto3 | 1.44.11 | 15.28 | 3 direct dependencies |
| 31 | tenacity | 9.2.1 | 8.94 | 4 releases in 2 years |
| 32 | loguru | 0.8.0 | 8.76 | 2 releases in 2 years |
| 33 | cryptography | 50.0.2 | 7.50 | no signal riskier than the baseline middle |
| 34 | pyjwt | 2.15.1 | 6.91 | no signal riskier than the baseline middle |
| 35 | tqdm | 4.70.1 | 6.34 | no signal riskier than the baseline middle |
| 36 | lxml | 6.1.3 | 6.32 | last upload 83 days ago |
| 37 | pillow | 13.0.0 | 5.33 | no signal riskier than the baseline middle |
| 38 | sqlalchemy | 2.1.9 | 3.52 | no signal riskier than the baseline middle |
| 39 | gunicorn | 27.0.1 | 2.03 | no signal riskier than the baseline middle |
| 40 | redis | 8.2.0 | 0.59 | no signal riskier than the baseline middle |

## Top 10 recommendations

Produced by the agent; code validated every fact it cites against the PyPI data (facts validated; suitability not verified). The cited evidence and the agent's tool calls are in `results.json`.

### 1. pycrypto: replace with `pycryptodome` (PyPI package)

pycrypto 2.6.1 has 2 distinct known vulnerabilities with no fixed version listed, so no upgrade can fix them. pycryptodome has no flags and scores 1.67 against pycrypto's 99.96.

Assumptions: pycryptodome is assumed to be a largely API-compatible drop-in for pycrypto, for example through its Crypto namespace; Migration effort is assumed to be small, but it is not verified.

### 2. typing: replace with `typing` (standard-library module)

S4 = 4: pip falls back to an older release because newer allowed releases cannot install on 3.12, and S5 = 1 means sdist only, built from source at install. The python_fallback flag is set. The name typing is a Python 3.12 standard-library module, so the PyPI backport is not needed.

Assumptions: The stdlib typing module covers the APIs the code uses; imports stay 'import typing'; Migration effort is only removing the PyPI dependency from requirements.

### 3. futures: replace with `concurrent.futures` (standard-library module)

S4 = 4: pip falls back to an older release because newer allowed releases cannot install on 3.12, and S5 = 1 means the effective version is sdist only, built from source at install. The concurrent.futures module is in the Python 3.12 standard library, so the package is not needed.

Assumptions: The stdlib concurrent.futures API is equivalent to the futures backport for the features the code uses; Migration effort is small: imports already use concurrent.futures, so only the dependency needs removing.

### 4. nose: replace with `pytest` (PyPI package)

S1 shows 4194.2 days since the last upload, the largest score contribution. pytest scores 40.89 against nose's 96.34 on the same baseline and has no flags. S4 is 2 for nose, meaning no requires_python declaration and no Python 3 minor-version classifiers.

Assumptions: pytest can run the existing nose-style tests, possibly with test rewrites; Migration effort is moderate and has not been verified.

### 5. enum34: replace with `enum` (standard-library module)

S1 shows 2450.8 days since the last upload, and S4 shows only classifiers for older Python 3 versions. The enum module is part of the Python 3.12 standard library, so the backport should not be needed.

Assumptions: The stdlib enum API covers the usage in this code, since enum34 is a backport of it; Migration only means removing enum34 and keeping the existing 'import enum' lines.

### 6. pathlib: replace with `pathlib` (standard-library module)

S4 is 3 (only classifiers for older Python 3 versions) and S1 is 1666 days since the last upload. pathlib is a Python 3.12 standard-library module, so the PyPI package is not needed.

Assumptions: The code only uses the standard pathlib API, which the stdlib module provides; Migration effort is low: removing the PyPI dependency makes imports resolve to the stdlib module.

### 7. flask: upgrade to `>=3.1.3`

The specifier flask>=2.0 allows the floor version 2.0.0, which has known advisories, including GHSA-68rp-wp8r-4726 fixed in 3.1.3. Release 3.1.3 is final, not yanked, eligible on 3.12 and has no vulnerabilities. Raising the lower bound to 3.1.3 excludes the affected releases.

Assumptions: Application code is compatible with Flask 3.x APIs.

### 8. celery: upgrade to `>=5.2.2`

The floor version 5.0.0 allowed by celery>=5.0 carries advisory PYSEC-2021-858 (also GHSA-q4xr-rc97-m4xx), fixed in 5.2.2. Version 5.2.2 is final, not yanked, eligible and lists no vulnerabilities, so raising the lower bound excludes the affected releases.

Assumptions: Code written for 5.0/5.1 works unchanged on 5.2.2 and later within major 5.

### 9. six: do nothing

The two top signals are S1 (720.8 days since the last non-yanked upload) and S2 (1 final release in the 24 months before T). Both are maintenance-age signals. The profile shows no known vulnerabilities (S6 = 0), a compatible wheel (S5 = 0), and the effective version 1.17.0 has no advisories. No version bound can address S1 or S2.

### 10. aiohttp: upgrade to `>=3.14.5`

The specifier >=3.8 still allows the floor version 3.8.0, which has many known advisories, such as GHSA-p998-jp59-783m. Version 3.14.5 is final, not yanked, eligible on 3.12 and lists no vulnerabilities, so raising the lower bound to it excludes the vulnerable releases.

Assumptions: Code written against aiohttp 3.8 APIs works on 3.14.x without changes; Python 3.10 or newer is available (3.14.5 requires >=3.10; the service runs 3.12).
