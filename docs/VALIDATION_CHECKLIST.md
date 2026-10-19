# Validation Checklist

## Before running a pilot

- [ ] Dataset version and sample count verified.
- [ ] Ground-truth labels loaded and mapped correctly.
- [ ] All required prompt IDs registered.
- [ ] Prompt versions and source/adaptation notes recorded.
- [ ] Ollama endpoint available.
- [ ] Required model tags verified.
- [ ] Gemma thinking support verified separately.
- [ ] FindSecBugs version and results validated.
- [ ] SAST findings mapped to the correct test cases.
- [ ] LLM-only prompts contain no SAST information.
- [ ] Ground-truth labels are not included in prompts.
- [ ] Output schema validated.
- [ ] Result keys distinguish model, prompt, SAST condition, and thinking setting.
- [ ] Resume behavior tested.
- [ ] Metric calculations tested against known confusion-matrix examples.

## Before the full experiment

- [ ] Pilot run completed and manually inspected.
- [ ] All required scenarios have valid configuration.
- [ ] Failures and missing results are accounted for.
- [ ] Raw responses and per-sample predictions are preserved.
- [ ] Summary metrics match the underlying predictions.
- [ ] Estimated runtime and storage are acceptable.
- [ ] Full run explicitly approved by the user.

## Implementation validation state

- The manager validates the exact eight approved mappings and all referenced templates; parser contracts are strategy-aware. The ToT condition adaptations are version 2 to suppress intermediate reasoning disclosure; the change is documented in the prompt catalog.
- Scenario state is sample-attempt-aware. A successful single sample is not a completed full-dataset scenario; scenarios become completed only when the entire registered dataset scope has valid artifacts. Failures, invalid responses, missing IDs, and artifact checksum mismatches remain visible after restart.
- `validate` reports configuration, environment, prerequisite, and pilot-readiness states separately. Exit code `0` means the selected readiness check passed without inference; `1` means prerequisites remain blocked; `2` means invalid configuration/CLI or environment/model failure. A manual task command cannot mark evidence-backed prerequisites completed.
- Dataset CSV, label/CWE mapping, and source-manifest are not supplied in this checkout. Final dataset identity/provenance and ground-truth verification are blocked. The manifest validator checks row shape/count/uniqueness, labels, CWE syntax, mapping agreement and checksums; source/reviewer declarations are not cryptographic proof and need independent human verification.
- FindSecBugs execution and artifacts are not supplied. This repository has no scanner pipeline; SAST scenarios remain blocked until externally generated, sample-keyed results and checksummed provenance manifest are reviewed.
- Ollama and model tags were not rechecked during this audit; runtime availability and Gemma thinking support are assessed live by `validate`. No inference or pilot was run.

## Final readiness decision

A passing unit-test suite is not sufficient by itself. This checkout is **not ready for a pilot** until the OWASP Benchmark Java v1.2 data and mapping are staged and independently reviewed, and the selected configuration's runtime/model (plus FindSecBugs for SAST configurations) is verified. A one-sample pilot remains the next allowed experimental action after those prerequisites; the full matrix is not authorized by validation.