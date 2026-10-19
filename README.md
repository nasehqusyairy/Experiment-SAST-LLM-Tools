# Experiment-SAST-LLM-Tools

This repository contains research utilities for evaluating Java vulnerability detection with LLM prompts and static-analysis context. The experiment protocol, approved prompt registry, source-paper evidence, adaptations, and validation requirements are documented in `docs/`.

## Safe experiment manager

The persistent CLI is the supported experiment entry point. It runs only an explicitly selected sample and configuration, stores task/scenario state in SQLite, preserves the input prompt and raw response, and refuses to overwrite outputs.

```bash
python3 runExperiment.py status
python3 runExperiment.py validate
python3 runExperiment.py task dataset completed --detail "verified local OWASP Benchmark Java v1.2"
python3 runExperiment.py run --config zero-shot-none --model qwen2.5-coder:7b --dataset /path/benchmark.csv --sample BenchmarkTest00001
python3 runExperiment.py summary --dataset /path/benchmark.csv --scenario-dir experiment_runs/qwen2.5-coder:7b__zero-shot-none__standard --output summaries/pilot.json
```

The dataset CSV contract is described in `docs/EXPERIMENT_MANAGER.md`. Do not mark a setup task complete until it is verified. The full OWASP Benchmark Java v1.2 dataset and its label mapping are not bundled. FindSecBugs output must be verified and sample-keyed before running any SAST configuration. The three standard models and optional Gemma thinking capability are checked through the local Ollama API.

The eight approved prompt configurations are separate from the five prompt source files. Runtime templates live in `prompts/`; Munson condition adaptations are version-controlled under `prompts/munson_adaptations/`. See `docs/PROMPT_CATALOG.md` for source status and deviations. Neither the CLI nor tests start the full matrix.

## Existing utilities

- `generateCSV.py`: legacy output-folder CSV utility.
- `cleanReferences.py`: OWASP Java source adjustment utility.
- `OWASP Benchmark Extension/CSVLLM.java`: legacy OWASP result integration.

## Tests

```bash
python3 -m unittest discover -s tests -v
```
