# Experiment-SAST-LLM-Tools

This repository contains research utilities for evaluating Java vulnerability detection with LLM prompts and static-analysis context. The experiment protocol, approved prompt registry, source-paper evidence, adaptations, and validation requirements are documented in `docs/`.

## Safe experiment manager

The persistent CLI is the supported experiment entry point. It runs only an explicitly selected sample and configuration, stores task/scenario state in SQLite, preserves the input prompt and raw response, and refuses to overwrite outputs.

```bash
python3 runExperiment.py status
python3 runExperiment.py validate --config zero-shot-none --model qwen2.5-coder:7b --dataset /path/benchmark.csv --dataset-manifest /path/dataset-manifest.json
python3 runExperiment.py run --config zero-shot-none --model qwen2.5-coder:7b --dataset /path/benchmark.csv --dataset-manifest /path/dataset-manifest.json --sample "$SAMPLE_ID"
python3 runExperiment.py summary --dataset /path/benchmark.csv --dataset-manifest /path/dataset-manifest.json --scenario-dir experiment_runs/SCENARIO_ID --output summaries/pilot.json
```

The dataset, normalized sample-keyed ground-truth mapping, provenance manifest, and FindSecBugs artifacts are not bundled. A manual task status cannot satisfy those prerequisites; `validate` and `run` recheck the files and current runtime. The selected sample's success is distinct from full-scenario completion: a scenario is complete only when its entire registered dataset scope has valid, checksum-matched predictions. See `docs/EXPERIMENT_MANAGER.md` for manifest schemas and validation exit codes. No runtime/model availability is claimed here; `validate` queries local Ollama without sending inference requests.

The eight approved prompt configurations are separate from the five prompt source files. Runtime templates live in `prompts/`; Munson condition adaptations are version-controlled under `prompts/munson_adaptations/`. See `docs/PROMPT_CATALOG.md` for source status and deviations. Neither the CLI nor tests start the full matrix.

## Existing utilities

- `generateCSV.py`: legacy output-folder CSV utility.
- `cleanReferences.py`: OWASP Java source adjustment utility.
- `OWASP Benchmark Extension/CSVLLM.java`: legacy OWASP result integration.

## Tests

```bash
python3 -m unittest discover -s tests -v
```
