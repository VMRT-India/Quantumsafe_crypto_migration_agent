# Module Contracts

This directory contains the detailed JSON schema specifications for every
inter-module data exchange type defined in `src/qsma/utils/models.py`.

These contracts enable parallel development: each developer can implement their
module against the schema without waiting for upstream/downstream modules to be complete.

## Contracts

| File | Schema | Produced by | Consumed by |
|---|---|---|---|
| `codebase_snapshot.md` | `CodebaseSnapshot` | Ingestion | Analyzer |
| `analysis_result.md` | `AnalysisResult` | Analyzer | Detector |
| `crypto_hit.md` | `CryptoHit` | Detector | Classifier |
| `crypto_finding.md` | `CryptoFinding` | Classifier | Planner, Reporter |
| `migration_plan.md` | `MigrationPlan` | Planner | Migrator |
| `transformation_result.md` | `TransformationResult` | Migrator | Validator, Reporter |
| `validation_result.md` | `ValidationResult` | Validator | Reporter |
| `scan_report.md` | `ScanReport` | Reporter | CLI output |

**Source of truth:** `src/qsma/utils/models.py`
These markdown files are documentation — the Python models are authoritative.
