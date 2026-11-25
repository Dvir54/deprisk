# Dependency risk report

Snapshot `5c1e0e851f88d945`, T = 2026-11-25T13:50:06.898024+00:00, baseline n = 4920, config `84831a861b3516fb`.

The score says how much riskier a package looks than the baseline: a score of X means its total is higher than X% of the baseline totals. It is a relative index, not a probability of failure, and unusual is not the same as unsafe. Each signal adds -ln(q), where q is the share of the baseline that is as risky or riskier.

## Ranking

| Rank | Package | Requirement | Effective version | Score | Total | Flags |
|---:|---|---|---|---:|---:|---|
| 1 | pycrypto | >=2.6 | 2.6.1 | 99.96 | 14.596 | missing:requires_dist, sdist_only, unfixed_advisory |
| 2 | typing | (any) | 3.7.4.3 | 99.29 | 7.095 | missing:requires_dist, python_fallback, sdist_only |
| 3 | futures | (any) | 3.0.5 | 99.11 | 6.842 | missing:requires_dist, python_fallback, sdist_only |
| 4 | nose | (any) | 1.3.7 | 96.34 | 5.255 | missing:requires_dist |
| 5 | enum34 | (any) | 1.1.10 | 93.54 | 4.483 | missing:requires_dist |
| 6 | pathlib | (any) | 1.0.1 | 90.81 | 4.052 | missing:requires_dist |
| 7 | flask | >=2.0 | 3.1.3 | 81.36 | 3.104 | - |
| 8 | celery | >=5.0 | 5.7.0 | 77.09 | 2.826 | - |
| 9 | six | (any) | 1.17.0 | 72.97 | 2.572 | missing:requires_dist |
| 10 | aiohttp | >=3.8 | 3.14.5 | 72.34 | 2.536 | - |
| 11 | httpx | >=0.23 | 0.28.1 | 57.93 | 1.973 | - |
| 12 | jinja2 | >=3.0 | 3.1.6 | 55.75 | 1.905 | - |
| 13 | requests | >=2.25 | 2.34.2 | 53.88 | 1.859 | - |
| 14 | arrow | >=1.0 | 1.4.0 | 50.43 | 1.755 | - |
| 15 | retrying | >=1.3 | 1.4.2 | 49.27 | 1.723 | missing:requires_dist |
| 16 | beautifulsoup4 | >=4.10 | 4.15.0 | 45.22 | 1.619 | - |
| 17 | click | >=8.0 | 8.5.1 | 40.10 | 1.484 | missing:requires_dist |
| 18 | psycopg2-binary | >=2.9 | 2.9.13 | 38.60 | 1.444 | missing:requires_dist |
| 19 | mock | >=4.0 | 5.2.0 | 36.10 | 1.383 | - |
| 20 | pydantic | >=1.10 | 2.14.4 | 30.30 | 1.247 | - |
| 21 | pyyaml | >=5.4 | 6.0.4 | 29.94 | 1.241 | missing:requires_dist |
| 22 | pendulum | >=2.1 | 3.3.0 | 27.70 | 1.185 | - |
| 23 | alembic | >=1.7 | 1.20.1 | 26.18 | 1.142 | - |
| 24 | pytz | (any) | 2026.6 | 24.67 | 1.094 | missing:requires_dist |
| 25 | simplejson | >=3.17 | 4.3.0 | 23.07 | 1.051 | missing:requires_dist |
| 26 | marshmallow | >=3.14 | 4.4.0 | 19.74 | 0.963 | missing:requires_dist |
| 27 | numpy | >=1.21 | 2.5.5 | 17.09 | 0.890 | missing:requires_dist |
| 28 | python-dateutil | >=2.8 | 4.0.0 | 16.30 | 0.870 | - |
| 29 | pandas | >=1.3 | 3.1.1 | 16.02 | 0.859 | - |
| 30 | boto3 | >=1.20 | 1.44.11 | 15.28 | 0.826 | - |
| 31 | tenacity | >=8.0 | 9.2.1 | 8.94 | 0.634 | - |
| 32 | loguru | >=0.5 | 0.8.0 | 8.76 | 0.627 | - |
| 33 | cryptography | >=3.4 | 50.0.2 | 7.50 | 0.572 | - |
| 34 | pyjwt | >=2.0 | 2.15.1 | 6.91 | 0.547 | - |
| 35 | tqdm | >=4.60 | 4.70.1 | 6.34 | 0.526 | - |
| 36 | lxml | >=4.6 | 6.1.3 | 6.32 | 0.526 | - |
| 37 | pillow | >=9.0 | 13.0.0 | 5.33 | 0.467 | - |
| 38 | sqlalchemy | >=1.4 | 2.1.9 | 3.52 | 0.350 | - |
| 39 | gunicorn | >=20.0 | 27.0.1 | 2.03 | 0.270 | - |
| 40 | redis | >=4.0 | 8.2.0 | 0.59 | 0.131 | - |

## Package details

### 1. pycrypto

Score **99.96** (riskier than 99.96% of the baseline), total 14.596. Effective version 2.6.1, reference version 2.6.1. Categories: maintenance 3.949, compatibility 2.552, security 7.402, dependencies 0.693.

Signals driving the score:
- S6 distinct vulnerabilities on the reference version: 2; only 0.06% of the baseline is as risky or riskier (contribution 7.402)
- S1 days since the last upload: 4541 days; only 0.18% of the baseline is as risky or riskier (contribution 6.304)
- S5 install path: state 1: sdist only (build required); only 4.59% of the baseline is as risky or riskier (contribution 3.081)
- S4 Python 3.12 evidence: state 2: no requires_python and no Python 3 minor classifiers; only 13.21% of the baseline is as risky or riskier (contribution 2.024)
- S2 final releases in the last 24 months: 0; only 20.33% of the baseline is as risky or riskier (contribution 1.593)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "2.6.1"}
- `sdist_only`: {"S5": 1, "effective_version": "2.6.1"}
- `unfixed_advisory`: {"version": "2.6.1", "vulnerabilities": [{"aliases": ["CVE-2018-6594"], "fixed_in": [], "ids": ["GHSA-6528-wvf6-f6qg", "PYSEC-2018-97"]}, {"aliases": ["CVE-2013-7459"], "fixed_in": [], "ids": ["GHSA-cq27-v7xp-c356", "PYSEC-2017-94"]}]}

Evidence only (not scored): effective version age (days): 4541.24, PyPI role accounts: 2, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 2. typing

Score **99.29** (riskier than 99.29% of the baseline), total 7.095. Effective version 3.7.4.3, reference version 3.7.4.3. Categories: maintenance 2.221, compatibility 4.181, security 0.000, dependencies 0.693.

Signals driving the score:
- S4 Python 3.12 evidence: state 4: pip falls back to an older release; only 0.51% of the baseline is as risky or riskier (contribution 5.282)
- S5 install path: state 1: sdist only (build required); only 4.59% of the baseline is as risky or riskier (contribution 3.081)
- S1 days since the last upload: 2034 days; only 5.79% of the baseline is as risky or riskier (contribution 2.849)
- S2 final releases in the last 24 months: 0; only 20.33% of the baseline is as risky or riskier (contribution 1.593)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "3.7.4.3"}
- `python_fallback`: {"S4": 4, "effective_version": "3.7.4.3"}
- `sdist_only`: {"S5": 1, "effective_version": "3.7.4.3"}

Evidence only (not scored): effective version age (days): 2325.60, PyPI role accounts: 8, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 3. futures

Score **99.11** (riskier than 99.11% of the baseline), total 6.842. Effective version 3.0.5, reference version 3.0.5. Categories: maintenance 1.968, compatibility 4.181, security 0.000, dependencies 0.693.

Signals driving the score:
- S4 Python 3.12 evidence: state 4: pip falls back to an older release; only 0.51% of the baseline is as risky or riskier (contribution 5.282)
- S5 install path: state 1: sdist only (build required); only 4.59% of the baseline is as risky or riskier (contribution 3.081)
- S1 days since the last upload: 1486 days; only 9.61% of the baseline is as risky or riskier (contribution 2.342)
- S2 final releases in the last 24 months: 0; only 20.33% of the baseline is as risky or riskier (contribution 1.593)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "3.0.5"}
- `python_fallback`: {"S4": 4, "effective_version": "3.0.5"}
- `sdist_only`: {"S5": 1, "effective_version": "3.0.5"}

Evidence only (not scored): effective version age (days): 3936.67, PyPI role accounts: 2, share of fully yanked releases: 0.08, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 4. nose

Score **96.34** (riskier than 96.34% of the baseline), total 5.255. Effective version 1.3.7, reference version 1.3.7. Categories: maintenance 3.549, compatibility 1.012, security 0.000, dependencies 0.693.

Signals driving the score:
- S1 days since the last upload: 4194 days; only 0.41% of the baseline is as risky or riskier (contribution 5.505)
- S4 Python 3.12 evidence: state 2: no requires_python and no Python 3 minor classifiers; only 13.21% of the baseline is as risky or riskier (contribution 2.024)
- S2 final releases in the last 24 months: 0; only 20.33% of the baseline is as risky or riskier (contribution 1.593)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "1.3.7"}

Evidence only (not scored): effective version age (days): 4194.19, PyPI role accounts: 3, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 5. enum34

Score **93.54** (riskier than 93.54% of the baseline), total 4.483. Effective version 1.1.10, reference version 1.1.10. Categories: maintenance 2.456, compatibility 1.333, security 0.000, dependencies 0.693.

Signals driving the score:
- S1 days since the last upload: 2451 days; only 3.62% of the baseline is as risky or riskier (contribution 3.319)
- S4 Python 3.12 evidence: state 3: only stale Python 3 classifiers (< 3.12); only 6.95% of the baseline is as risky or riskier (contribution 2.666)
- S2 final releases in the last 24 months: 0; only 20.33% of the baseline is as risky or riskier (contribution 1.593)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "1.1.10"}

Evidence only (not scored): effective version age (days): 2450.83, PyPI role accounts: 1, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 6. pathlib

Score **90.81** (riskier than 90.81% of the baseline), total 4.052. Effective version 1.0.1, reference version 1.0.1. Categories: maintenance 2.026, compatibility 1.333, security 0.000, dependencies 0.693.

Signals driving the score:
- S4 Python 3.12 evidence: state 3: only stale Python 3 classifiers (< 3.12); only 6.95% of the baseline is as risky or riskier (contribution 2.666)
- S1 days since the last upload: 1666 days; only 8.56% of the baseline is as risky or riskier (contribution 2.458)
- S2 final releases in the last 24 months: 0; only 20.33% of the baseline is as risky or riskier (contribution 1.593)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "1.0.1"}

Evidence only (not scored): effective version age (days): 4465.92, PyPI role accounts: 1, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 7. flask

Score **81.36** (riskier than 81.36% of the baseline), total 3.104. Effective version 3.1.3, reference version 3.1.3. Categories: maintenance 0.953, compatibility 0.460, security 0.000, dependencies 1.692.

Signals driving the score:
- S7 direct runtime dependencies: 6; only 18.42% of the baseline is as risky or riskier (contribution 1.692)
- S1 days since the last upload: 279 days; only 34.17% of the baseline is as risky or riskier (contribution 1.074)
- S4 Python 3.12 evidence: state 1: requires_python declared, no 3.12 evidence; only 39.88% of the baseline is as risky or riskier (contribution 0.919)
- S2 final releases in the last 24 months: 3; only 43.52% of the baseline is as risky or riskier (contribution 0.832)

Evidence only (not scored): effective version age (days): 279.37, PyPI role accounts: 0, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 8. celery

Score **77.09** (riskier than 77.09% of the baseline), total 2.826. Effective version 5.7.0, reference version 5.7.0. Categories: maintenance 0.382, compatibility 0.000, security 0.000, dependencies 2.444.

Signals driving the score:
- S7 direct runtime dependencies: 9; only 8.68% of the baseline is as risky or riskier (contribution 2.444)
- S2 final releases in the last 24 months: 9; only 64.11% of the baseline is as risky or riskier (contribution 0.445)
- S1 days since the last upload: 20 days; only 72.66% of the baseline is as risky or riskier (contribution 0.319)

Evidence only (not scored): effective version age (days): 19.94, PyPI role accounts: 5, share of fully yanked releases: 0.01, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 9. six

Score **72.97** (riskier than 72.97% of the baseline), total 2.572. Effective version 1.17.0, reference version 1.17.0. Categories: maintenance 1.419, compatibility 0.460, security 0.000, dependencies 0.693.

Signals driving the score:
- S1 days since the last upload: 721 days; only 20.26% of the baseline is as risky or riskier (contribution 1.596)
- S2 final releases in the last 24 months: 1; only 28.86% of the baseline is as risky or riskier (contribution 1.243)
- S4 Python 3.12 evidence: state 1: requires_python declared, no 3.12 evidence; only 39.88% of the baseline is as risky or riskier (contribution 0.919)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "1.17.0"}

Evidence only (not scored): effective version age (days): 720.84, PyPI role accounts: 1, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 10. aiohttp

Score **72.34** (riskier than 72.34% of the baseline), total 2.536. Effective version 3.14.5, reference version 3.14.5. Categories: maintenance 0.330, compatibility 0.000, security 0.000, dependencies 2.206.

Signals driving the score:
- S7 direct runtime dependencies: 8; only 11.01% of the baseline is as risky or riskier (contribution 2.206)
- S1 days since the last upload: 46 days; only 58.98% of the baseline is as risky or riskier (contribution 0.528)
- S2 final releases in the last 24 months: 34; only 87.60% of the baseline is as risky or riskier (contribution 0.132)

Evidence only (not scored): effective version age (days): 45.54, PyPI role accounts: 5, share of fully yanked releases: 0.02, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 11. httpx

Score **57.93** (riskier than 57.93% of the baseline), total 1.973. Effective version 0.28.1, reference version 0.28.1. Categories: maintenance 0.849, compatibility 0.000, security 0.000, dependencies 1.124.

Signals driving the score:
- S7 direct runtime dependencies: 4; only 32.50% of the baseline is as risky or riskier (contribution 1.124)
- S2 final releases in the last 24 months: 2; only 36.97% of the baseline is as risky or riskier (contribution 0.995)
- S1 days since the last upload: 86 days; only 49.53% of the baseline is as risky or riskier (contribution 0.703)

Evidence only (not scored): effective version age (days): 718.93, PyPI role accounts: 2, share of fully yanked releases: 0.00, 0.x reference version: True, 'Development Status :: 7 - Inactive': False.

### 12. jinja2

Score **55.75** (riskier than 55.75% of the baseline), total 1.905. Effective version 3.1.6, reference version 3.1.6. Categories: maintenance 1.258, compatibility 0.460, security 0.000, dependencies 0.187.

Signals driving the score:
- S1 days since the last upload: 630 days; only 21.83% of the baseline is as risky or riskier (contribution 1.522)
- S2 final releases in the last 24 months: 2; only 36.97% of the baseline is as risky or riskier (contribution 0.995)
- S4 Python 3.12 evidence: state 1: requires_python declared, no 3.12 evidence; only 39.88% of the baseline is as risky or riskier (contribution 0.919)
- S7 direct runtime dependencies: 1; only 82.98% of the baseline is as risky or riskier (contribution 0.187)

Evidence only (not scored): effective version age (days): 629.74, PyPI role accounts: 0, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 13. requests

Score **53.88** (riskier than 53.88% of the baseline), total 1.859. Effective version 2.34.2, reference version 2.34.2. Categories: maintenance 0.735, compatibility 0.000, security 0.000, dependencies 1.124.

Signals driving the score:
- S7 direct runtime dependencies: 4; only 32.50% of the baseline is as risky or riskier (contribution 1.124)
- S1 days since the last upload: 195 days; only 39.29% of the baseline is as risky or riskier (contribution 0.934)
- S2 final releases in the last 24 months: 7; only 58.48% of the baseline is as risky or riskier (contribution 0.537)

Evidence only (not scored): effective version age (days): 194.77, PyPI role accounts: 3, share of fully yanked releases: 0.01, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 14. arrow

Score **50.43** (riskier than 50.43% of the baseline), total 1.755. Effective version 1.4.0, reference version 1.4.0. Categories: maintenance 1.244, compatibility 0.000, security 0.000, dependencies 0.511.

Signals driving the score:
- S1 days since the last upload: 403 days; only 28.78% of the baseline is as risky or riskier (contribution 1.245)
- S2 final releases in the last 24 months: 1; only 28.86% of the baseline is as risky or riskier (contribution 1.243)
- S7 direct runtime dependencies: 2; only 60.01% of the baseline is as risky or riskier (contribution 0.511)

Evidence only (not scored): effective version age (days): 402.84, PyPI role accounts: 4, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 15. retrying

Score **49.27** (riskier than 49.27% of the baseline), total 1.723. Effective version 1.4.2, reference version 1.4.2. Categories: maintenance 1.030, compatibility 0.000, security 0.000, dependencies 0.693.

Signals driving the score:
- S1 days since the last upload: 479 days; only 26.22% of the baseline is as risky or riskier (contribution 1.339)
- S2 final releases in the last 24 months: 4; only 48.60% of the baseline is as risky or riskier (contribution 0.722)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "1.4.2"}

Evidence only (not scored): effective version age (days): 479.43, PyPI role accounts: 1, share of fully yanked releases: 0.11, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 16. beautifulsoup4

Score **45.22** (riskier than 45.22% of the baseline), total 1.619. Effective version 4.15.0, reference version 4.15.0. Categories: maintenance 0.649, compatibility 0.460, security 0.000, dependencies 0.511.

Signals driving the score:
- S4 Python 3.12 evidence: state 1: requires_python declared, no 3.12 evidence; only 39.88% of the baseline is as risky or riskier (contribution 0.919)
- S1 days since the last upload: 171 days; only 41.22% of the baseline is as risky or riskier (contribution 0.886)
- S7 direct runtime dependencies: 2; only 60.01% of the baseline is as risky or riskier (contribution 0.511)
- S2 final releases in the last 24 months: 10; only 66.30% of the baseline is as risky or riskier (contribution 0.411)

Evidence only (not scored): effective version age (days): 170.88, PyPI role accounts: 1, share of fully yanked releases: 0.02, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 17. click

Score **40.10** (riskier than 40.10% of the baseline), total 1.484. Effective version 8.5.1, reference version 8.5.1. Categories: maintenance 0.332, compatibility 0.460, security 0.000, dependencies 0.693.

Signals driving the score:
- S4 Python 3.12 evidence: state 1: requires_python declared, no 3.12 evidence; only 39.88% of the baseline is as risky or riskier (contribution 0.919)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)
- S2 final releases in the last 24 months: 12; only 69.94% of the baseline is as risky or riskier (contribution 0.358)
- S1 days since the last upload: 19 days; only 73.68% of the baseline is as risky or riskier (contribution 0.305)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "8.5.1"}

Evidence only (not scored): effective version age (days): 18.84, PyPI role accounts: 0, share of fully yanked releases: 0.02, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 18. psycopg2-binary

Score **38.60** (riskier than 38.60% of the baseline), total 1.444. Effective version 2.9.13, reference version 2.9.13. Categories: maintenance 0.751, compatibility 0.000, security 0.000, dependencies 0.693.

Signals driving the score:
- S2 final releases in the last 24 months: 3; only 43.52% of the baseline is as risky or riskier (contribution 0.832)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)
- S1 days since the last upload: 77 days; only 51.16% of the baseline is as risky or riskier (contribution 0.670)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "2.9.13"}

Evidence only (not scored): effective version age (days): 76.58, PyPI role accounts: 1, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 19. mock

Score **36.10** (riskier than 36.10% of the baseline), total 1.383. Effective version 5.2.0, reference version 5.2.0. Categories: maintenance 1.383, compatibility 0.000, security 0.000, dependencies 0.000.

Signals driving the score:
- S1 days since the last upload: 632 days; only 21.79% of the baseline is as risky or riskier (contribution 1.524)
- S2 final releases in the last 24 months: 1; only 28.86% of the baseline is as risky or riskier (contribution 1.243)

Evidence only (not scored): effective version age (days): 632.05, PyPI role accounts: 6, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 20. pydantic

Score **30.30** (riskier than 30.30% of the baseline), total 1.247. Effective version 2.14.4, reference version 2.14.4. Categories: maintenance 0.123, compatibility 0.000, security 0.000, dependencies 1.124.

Signals driving the score:
- S7 direct runtime dependencies: 4; only 32.50% of the baseline is as risky or riskier (contribution 1.124)
- S1 days since the last upload: 6 days; only 87.03% of the baseline is as risky or riskier (contribution 0.139)
- S2 final releases in the last 24 months: 40; only 89.86% of the baseline is as risky or riskier (contribution 0.107)

Evidence only (not scored): effective version age (days): 6.04, PyPI role accounts: 2, share of fully yanked releases: 0.01, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 21. pyyaml

Score **29.94** (riskier than 29.94% of the baseline), total 1.241. Effective version 6.0.4, reference version 6.0.4. Categories: maintenance 0.548, compatibility 0.000, security 0.000, dependencies 0.693.

Signals driving the score:
- S2 final releases in the last 24 months: 2; only 36.97% of the baseline is as risky or riskier (contribution 0.995)
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)
- S1 days since the last upload: 5 days; only 90.35% of the baseline is as risky or riskier (contribution 0.102)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "6.0.4"}

Evidence only (not scored): effective version age (days): 4.59, PyPI role accounts: 3, share of fully yanked releases: 0.03, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 22. pendulum

Score **27.70** (riskier than 27.70% of the baseline), total 1.185. Effective version 3.3.0, reference version 3.3.0. Categories: maintenance 0.674, compatibility 0.000, security 0.000, dependencies 0.511.

Signals driving the score:
- S2 final releases in the last 24 months: 3; only 43.52% of the baseline is as risky or riskier (contribution 0.832)
- S1 days since the last upload: 44 days; only 59.67% of the baseline is as risky or riskier (contribution 0.516)
- S7 direct runtime dependencies: 2; only 60.01% of the baseline is as risky or riskier (contribution 0.511)

Evidence only (not scored): effective version age (days): 43.71, PyPI role accounts: 2, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 23. alembic

Score **26.18** (riskier than 26.18% of the baseline), total 1.142. Effective version 1.20.1, reference version 1.20.1. Categories: maintenance 0.329, compatibility 0.000, security 0.000, dependencies 0.813.

Signals driving the score:
- S7 direct runtime dependencies: 3; only 44.36% of the baseline is as risky or riskier (contribution 0.813)
- S1 days since the last upload: 34 days; only 63.05% of the baseline is as risky or riskier (contribution 0.461)
- S2 final releases in the last 24 months: 23; only 82.13% of the baseline is as risky or riskier (contribution 0.197)

Evidence only (not scored): effective version age (days): 34.43, PyPI role accounts: 2, share of fully yanked releases: 0.01, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 24. pytz

Score **24.67** (riskier than 24.67% of the baseline), total 1.094. Effective version 2026.6, reference version 2026.6. Categories: maintenance 0.401, compatibility 0.000, security 0.000, dependencies 0.693.

Signals driving the score:
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)
- S2 final releases in the last 24 months: 10; only 66.30% of the baseline is as risky or riskier (contribution 0.411)
- S1 days since the last upload: 27 days; only 67.60% of the baseline is as risky or riskier (contribution 0.392)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "2026.6"}

Evidence only (not scored): effective version age (days): 27.20, PyPI role accounts: 1, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 25. simplejson

Score **23.07** (riskier than 23.07% of the baseline), total 1.051. Effective version 4.3.0, reference version 4.3.0. Categories: maintenance 0.358, compatibility 0.000, security 0.000, dependencies 0.693.

Signals driving the score:
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)
- S2 final releases in the last 24 months: 9; only 64.11% of the baseline is as risky or riskier (contribution 0.445)
- S1 days since the last upload: 15 days; only 76.20% of the baseline is as risky or riskier (contribution 0.272)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "4.3.0"}

Evidence only (not scored): effective version age (days): 14.71, PyPI role accounts: 3, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 26. marshmallow

Score **19.74** (riskier than 19.74% of the baseline), total 0.963. Effective version 4.4.0, reference version 4.4.0. Categories: maintenance 0.270, compatibility 0.000, security 0.000, dependencies 0.693.

Signals driving the score:
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)
- S1 days since the last upload: 22 days; only 70.94% of the baseline is as risky or riskier (contribution 0.343)
- S2 final releases in the last 24 months: 23; only 82.13% of the baseline is as risky or riskier (contribution 0.197)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "4.4.0"}

Evidence only (not scored): effective version age (days): 21.57, PyPI role accounts: 2, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 27. numpy

Score **17.09** (riskier than 17.09% of the baseline), total 0.890. Effective version 2.5.5, reference version 2.5.5. Categories: maintenance 0.197, compatibility 0.000, security 0.000, dependencies 0.693.

Signals driving the score:
- S7 direct runtime dependencies: unknown (metadata missing); neutral placement (no data) (contribution 0.693)
- S1 days since the last upload: 10 days; only 81.04% of the baseline is as risky or riskier (contribution 0.210)
- S2 final releases in the last 24 months: 25; only 83.21% of the baseline is as risky or riskier (contribution 0.184)

Flags:
- `missing:requires_dist`: {"field": "requires_dist", "value": null, "version": "2.5.5"}

Evidence only (not scored): effective version age (days): 9.68, PyPI role accounts: 3, share of fully yanked releases: 0.01, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 28. python-dateutil

Score **16.30** (riskier than 16.30% of the baseline), total 0.870. Effective version 4.0.0, reference version 4.0.0. Categories: maintenance 0.683, compatibility 0.000, security 0.000, dependencies 0.187.

Signals driving the score:
- S2 final releases in the last 24 months: 2; only 36.97% of the baseline is as risky or riskier (contribution 0.995)
- S1 days since the last upload: 24 days; only 68.94% of the baseline is as risky or riskier (contribution 0.372)
- S7 direct runtime dependencies: 1; only 82.98% of the baseline is as risky or riskier (contribution 0.187)

Evidence only (not scored): effective version age (days): 24.28, PyPI role accounts: 4, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 29. pandas

Score **16.02** (riskier than 16.02% of the baseline), total 0.859. Effective version 3.1.1, reference version 3.1.1. Categories: maintenance 0.348, compatibility 0.000, security 0.000, dependencies 0.511.

Signals driving the score:
- S7 direct runtime dependencies: 2; only 60.01% of the baseline is as risky or riskier (contribution 0.511)
- S2 final releases in the last 24 months: 12; only 69.94% of the baseline is as risky or riskier (contribution 0.358)
- S1 days since the last upload: 21 days; only 71.30% of the baseline is as risky or riskier (contribution 0.338)

Evidence only (not scored): effective version age (days): 20.95, PyPI role accounts: 3, share of fully yanked releases: 0.01, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 30. boto3

Score **15.28** (riskier than 15.28% of the baseline), total 0.826. Effective version 1.44.11, reference version 1.44.11. Categories: maintenance 0.013, compatibility 0.000, security 0.000, dependencies 0.813.

Signals driving the score:
- S7 direct runtime dependencies: 3; only 44.36% of the baseline is as risky or riskier (contribution 0.813)
- S1 days since the last upload: 1 days; only 97.56% of the baseline is as risky or riskier (contribution 0.025)
- S2 final releases in the last 24 months: 483; only 99.86% of the baseline is as risky or riskier (contribution 0.001)

Evidence only (not scored): effective version age (days): 0.73, PyPI role accounts: 1, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 31. tenacity

Score **8.94** (riskier than 8.94% of the baseline), total 0.634. Effective version 9.2.1, reference version 9.2.1. Categories: maintenance 0.634, compatibility 0.000, security 0.000, dependencies 0.000.

Signals driving the score:
- S2 final releases in the last 24 months: 4; only 48.60% of the baseline is as risky or riskier (contribution 0.722)
- S1 days since the last upload: 49 days; only 57.87% of the baseline is as risky or riskier (contribution 0.547)

Evidence only (not scored): effective version age (days): 49.07, PyPI role accounts: 2, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 32. loguru

Score **8.76** (riskier than 8.76% of the baseline), total 0.627. Effective version 0.8.0, reference version 0.8.0. Categories: maintenance 0.627, compatibility 0.000, security 0.000, dependencies 0.000.

Signals driving the score:
- S2 final releases in the last 24 months: 2; only 36.97% of the baseline is as risky or riskier (contribution 0.995)
- S1 days since the last upload: 14 days; only 77.26% of the baseline is as risky or riskier (contribution 0.258)

Evidence only (not scored): effective version age (days): 13.79, PyPI role accounts: 1, share of fully yanked releases: 0.00, 0.x reference version: True, 'Development Status :: 7 - Inactive': False.

### 33. cryptography

Score **7.50** (riskier than 7.50% of the baseline), total 0.572. Effective version 50.0.2, reference version 50.0.2. Categories: maintenance 0.385, compatibility 0.000, security 0.000, dependencies 0.187.

Signals driving the score:
- S1 days since the last upload: 56 days; only 55.12% of the baseline is as risky or riskier (contribution 0.596)
- S7 direct runtime dependencies: 1; only 82.98% of the baseline is as risky or riskier (contribution 0.187)
- S2 final releases in the last 24 months: 26; only 83.98% of the baseline is as risky or riskier (contribution 0.175)

Evidence only (not scored): effective version age (days): 55.96, PyPI role accounts: 1, share of fully yanked releases: 0.02, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 34. pyjwt

Score **6.91** (riskier than 6.91% of the baseline), total 0.547. Effective version 2.15.1, reference version 2.15.1. Categories: maintenance 0.547, compatibility 0.000, security 0.000, dependencies 0.000.

Signals driving the score:
- S1 days since the last upload: 58 days; only 54.55% of the baseline is as risky or riskier (contribution 0.606)
- S2 final releases in the last 24 months: 8; only 61.44% of the baseline is as risky or riskier (contribution 0.487)

Evidence only (not scored): effective version age (days): 57.80, PyPI role accounts: 1, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 35. tqdm

Score **6.34** (riskier than 6.34% of the baseline), total 0.526. Effective version 4.70.1, reference version 4.70.1. Categories: maintenance 0.526, compatibility 0.000, security 0.000, dependencies 0.000.

Signals driving the score:
- S1 days since the last upload: 75 days; only 51.42% of the baseline is as risky or riskier (contribution 0.665)
- S2 final releases in the last 24 months: 11; only 67.97% of the baseline is as risky or riskier (contribution 0.386)

Evidence only (not scored): effective version age (days): 75.27, PyPI role accounts: 2, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 36. lxml

Score **6.32** (riskier than 6.32% of the baseline), total 0.526. Effective version 6.1.3, reference version 6.1.3. Categories: maintenance 0.526, compatibility 0.000, security 0.000, dependencies 0.000.

Signals driving the score:
- S1 days since the last upload: 83 days; only 49.98% of the baseline is as risky or riskier (contribution 0.694)
- S2 final releases in the last 24 months: 12; only 69.94% of the baseline is as risky or riskier (contribution 0.358)

Evidence only (not scored): effective version age (days): 83.96, PyPI role accounts: 2, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 37. pillow

Score **5.33** (riskier than 5.33% of the baseline), total 0.467. Effective version 13.0.0, reference version 13.0.0. Categories: maintenance 0.467, compatibility 0.000, security 0.000, dependencies 0.000.

Signals driving the score:
- S1 days since the last upload: 40 days; only 61.30% of the baseline is as risky or riskier (contribution 0.489)
- S2 final releases in the last 24 months: 9; only 64.11% of the baseline is as risky or riskier (contribution 0.445)

Evidence only (not scored): effective version age (days): 39.65, PyPI role accounts: 4, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 38. sqlalchemy

Score **3.52** (riskier than 3.52% of the baseline), total 0.350. Effective version 2.1.9, reference version 2.1.9. Categories: maintenance 0.163, compatibility 0.000, security 0.000, dependencies 0.187.

Signals driving the score:
- S7 direct runtime dependencies: 1; only 82.98% of the baseline is as risky or riskier (contribution 0.187)
- S1 days since the last upload: 9 days; only 83.17% of the baseline is as risky or riskier (contribution 0.184)
- S2 final releases in the last 24 months: 32; only 86.75% of the baseline is as risky or riskier (contribution 0.142)

Evidence only (not scored): effective version age (days): 8.70, PyPI role accounts: 2, share of fully yanked releases: 0.01, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 39. gunicorn

Score **2.03** (riskier than 2.03% of the baseline), total 0.270. Effective version 27.0.1, reference version 27.0.1. Categories: maintenance 0.270, compatibility 0.000, security 0.000, dependencies 0.000.

Signals driving the score:
- S2 final releases in the last 24 months: 15; only 74.17% of the baseline is as risky or riskier (contribution 0.299)
- S1 days since the last upload: 13 days; only 78.62% of the baseline is as risky or riskier (contribution 0.241)

Evidence only (not scored): effective version age (days): 12.63, PyPI role accounts: 2, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

### 40. redis

Score **0.59** (riskier than 0.59% of the baseline), total 0.131. Effective version 8.2.0, reference version 8.2.0. Categories: maintenance 0.131, compatibility 0.000, security 0.000, dependencies 0.000.

Signals driving the score:
- S2 final releases in the last 24 months: 24; only 82.72% of the baseline is as risky or riskier (contribution 0.190)
- S1 days since the last upload: 2 days; only 93.05% of the baseline is as risky or riskier (contribution 0.072)

Evidence only (not scored): effective version age (days): 2.22, PyPI role accounts: 3, share of fully yanked releases: 0.00, 0.x reference version: False, 'Development Status :: 7 - Inactive': False.

## Recommendations for the top packages

Not run (`--no-llm`).

## Baseline summary

- Definition: top 5000 PyPI projects by downloads (hugovk top-pypi-packages)
- Packages scored (n): 4920; excluded: data unavailable: 1, only pre-releases: 77, only yanked files: 2
- Top list last updated: 2026-11-01 06:41:05; reference time T: 2026-11-25T13:50:06.898024+00:00
- Totals: median 1.742, p90 3.971

| Signal | Meaning | Riskier when | n_s | Median | p90 | Ties at best | Unknown | Partial |
|---|---|---|---:|---:|---:|---:|---:|---:|
| S1 | days since the last upload | higher | 4920 | 82.849 | 1453.01 | 0.02% | 0 | 0 |
| S2 | final releases in the last 24 months | lower | 4920 | 5 | 41 | 0.02% | 0 | 0 |
| S4 | Python 3.12 evidence | higher | 4920 | 0 | 2 | 60.12% | 0 | 0 |
| S5 | install path | higher | 4920 | 0 | 0 | 95.41% | 0 | 0 |
| S6 | distinct vulnerabilities on the reference version | higher | 4920 | 0 | 0 | 99.78% | 0 | 0 |
| S7 | direct runtime dependencies | higher | 3778 | 2 | 8 | 17.02% | 1142 | 0 |
