# Experiment Manager Specification

## Goal

Provide an interactive CLI that tracks experiment preparation and execution from initial setup to final evaluation.

## Dashboard

Show:

- Environment and dependency status
- Ollama availability and model availability
- Dataset and ground-truth validation
- FindSecBugs setup and result availability
- Prompt registry validation
- Experiment scenario status
- Completed, pending, running, failed, and blocked tasks
- Log and output locations

## Interactive workflow

The CLI provides `status`, `validate`, `task`, `run`, and `summary`. Every `run` is one explicit sample/configuration invocation; the persistent scenario scope is the complete validated dataset. A completed sample does not complete its scenario. The full scenario becomes `completed` only when each required sample has a valid, checksum-verified prediction; failures and unprocessed sample IDs remain visible.

```bash
python3 runExperiment.py status
python3 runExperiment.py validate --config zero-shot-none --model qwen2.5-coder:7b --dataset /path/benchmark.csv --dataset-manifest /path/dataset-manifest.json
python3 runExperiment.py run --config zero-shot-none --model qwen2.5-coder:7b --dataset /path/benchmark.csv --dataset-manifest /path/dataset-manifest.json --sample "$SAMPLE_ID"
python3 runExperiment.py summary --dataset /path/benchmark.csv --dataset-manifest /path/dataset-manifest.json --scenario-dir experiment_runs/SCENARIO_ID --output summaries/pilot.json
```

The CSV must have `sample_id,java_source,target_cwe,vulnerable`; IDs must be unique, Java source nonempty and nonduplicated, labels explicit (`true/false`, `1/0`, `yes/no`), and target CWE canonical. Validation also requires exactly 2,740 rows and a checksummed normalized mapping CSV with `sample_id,target_cwe,vulnerable` matching every dataset row. A schema-1 dataset manifest must include `dataset_identity: OWASP Benchmark Java`, `version: "1.2"`, the official repository URL, its full source commit SHA, `sample_count`, the CSV checksum, `mapping_path`, `mapping_sha256`, and `provenance_review` fields (`reviewer`, ISO-8601 UTC `reviewed_at_utc`, and evidence reference). Hashes establish file integrity, not authenticity: source URL/revision and reviewer evidence are declarations, not cryptographic signatures, and still require independent human verification. The expected label is evaluation-only and never reaches the prompt renderer.

FindSecBugs is externally executed; this repository does not run the scanner. Its manifest must identify tool/version and analysis configuration, bind to the dataset SHA-256, include paths and SHA-256 checksums for scanner input and raw output artifacts, include a provenance review, and provide a `results` object keyed by exact dataset sample ID. For a full-scope `run`, every sample must have a successful result; for a sample-scoped `validate --sample`, at least that sample is checked, but the run command still requires complete dataset coverage. Each result has `status: "success"` and a `findings` list (possibly empty), or `status: "failed"` and an error. A zero-findings list is accepted only when the manifest records a successful analysis for that sample. Each normalized finding requires `rule_id` and `message`; optional fields are type-checked. No result can be borrowed from another sample. The manifest is an input contract and does not cryptographically prove FindSecBugs produced it.

`run` writes the rendered input, untouched model-response text, exact Ollama response-envelope bytes (including any separately returned `thinking` field), normalized prediction, attempt metadata, and failure/invalid-response records separately. The thinking channel is never parsed into a prediction or inserted into a prompt. Per-sample attempts have unique numbered paths; successful samples are skipped only after artifact hashes, sample ID, dataset hash, prompt hash, and the full experiment fingerprint (configuration, generation options, model/runtime details, SAST manifest, and thinking mode) are revalidated. Failed/invalid/running attempts are preserved and a later explicit run uses a new attempt path. SQLite tracks each attempt, full scenario scope, and task verification evidence/timestamps. A manual `task ... completed` is intentionally not accepted; dataset/SAST/model prerequisites are revalidated from artifacts/runtime on each validation or run. State defaults to `experiment_state.sqlite3`; use `--state` to isolate it.

`validate` exit codes: `0` = selected configuration/environment/prerequisites pass (no inference sent); `1` = valid configuration but pilot prerequisites remain blocked/missing; `2` = invalid configuration, model/runtime/environment failure, or CLI error. With no `--config`, validation covers all eight configurations and therefore requires a valid FindSecBugs manifest; select a `none` configuration to validate an LLM-only pilot. `--thinking` is valid only with `--model gemma4:e4b` and an `/api/show`-verified thinking control. No inference is sent by `validate`.

`summary` reports dataset size, valid prediction count, evaluated count, coverage, label counts, missing/invalid outputs, and metrics. Metrics use only samples with one valid normalized prediction; missing or invalid predictions are never treated as benign. A persistent evaluation record is separate from scenario completion: the report operation may finish with `completed` (full coverage) or `blocked` (partial coverage), while the experiment scenario remains independently `running` or `failed`. A failed summary operation is stored as `failed`. The CLI requires a dataset manifest, refuses to overwrite an existing summary, and returns `0` for complete coverage, `1` for a generated partial/blocked evaluation, or `2` for a summary failure.

## External references

- [OWASP Benchmark Java source and releases](https://github.com/OWASP-Benchmark/BenchmarkJava/releases). Version/sample provenance still needs to be checked against the exact staged artifact and source revision.
- [Ollama `/api/generate` documentation](https://docs.ollama.com/api/generate): the request `think` control and separately returned `thinking` field are preserved in request metadata and the raw API envelope; only `response` is parsed for predictions.
- [FindSecBugs project](https://github.com/find-sec-bugs/find-sec-bugs). This repository does not claim a native scanner pipeline or assume a raw output format; it accepts only the documented, reviewed normalized manifest plus checksummed raw input/output artifacts.

## State persistence

Persist task and scenario state across restarts. SQLite is preferred if suitable for the repository.

Support retries, explicit reruns, safe resume, logs, and failure details.

## Safety

Never overwrite results silently. Do not mark partial runs as completed. Detect missing prerequisites and explain how to resolve them.

Do not run the full benchmark during development. Begin with unit tests and a small smoke test.