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

The initial CLI implementation provides `status`, `validate`, `task`, `run`, and `summary` commands. It is non-interactive for now: each mutation requires explicit command arguments, and `run` requires a single configuration, model, dataset, sample, and (for SAST) findings file. It never expands a selection to the full matrix.

```bash
python3 runExperiment.py status
python3 runExperiment.py validate
python3 runExperiment.py task dataset pending --detail "dataset not staged"
python3 runExperiment.py run --config zero-shot-none --model qwen2.5-coder:7b --dataset /path/benchmark.csv --sample BenchmarkTest00001 --scenario-id pilot-zs-none
python3 runExperiment.py summary --dataset /path/benchmark.csv --scenario-dir experiment_runs/pilot-zs-none --output summaries/pilot-zs-none.json
```

Dataset CSV columns are `sample_id,java_source,target_cwe,vulnerable`. `target_cwe` must be a canonical CWE identifier (`CWE-<number>`) sourced from the verified benchmark mapping; the CLI rejects missing/non-canonical values rather than guessing. The target CWE is input context; `vulnerable` is evaluation-only and is never passed to the prompt renderer. IDs must be unique and labels explicitly parseable. For `findsecbugs`, provide a JSON object mapping each sample ID to a finding string/list/object; a key for the selected sample is mandatory, with `[]` representing a verified empty result. Missing keys are not treated as empty results. The validated full dataset must contain 2,740 samples; do not use a hand-made fixture as a pilot.

`run` writes input, untouched raw model response, and normalized prediction as separate files. A repeat on a fully completed selected sample skips safely. Partial artifacts block automatic resume; use a new scenario ID only after inspecting/archiving the partial outputs. Existing files are never overwritten. SQLite state is stored in `experiment_state.sqlite3` by default and can be isolated with `--state`.

The local validation command currently checks configured prompt mappings and the Ollama `/api/tags` endpoint. Dataset version/count/labels, FindSecBugs version/result provenance, and Gemma thinking support still require independent validation before a pilot. Thinking mode is not enabled by this implementation until the installed server/model's support can be explicitly established.

## State persistence

Persist task and scenario state across restarts. SQLite is preferred if suitable for the repository.

Support retries, explicit reruns, safe resume, logs, and failure details.

## Safety

Never overwrite results silently. Do not mark partial runs as completed. Detect missing prerequisites and explain how to resolve them.

Do not run the full benchmark during development. Begin with unit tests and a small smoke test.