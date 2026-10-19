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

- Prompt registry and all eight configuration mappings validate against runtime files; focused tests cover the five source files and condition-specific variants.
- Local Ollama API `/api/tags` was reachable. The three configured model tags were installed: `deepseek-coder:6.7b`, `qwen2.5-coder:7b`, and `gemma4:e4b`.
- Ollama `/api/show` reports the `thinking` capability for `gemma4:e4b`; a distinct, opt-in thinking scenario is registered only after this runtime capability check. No thinking inference has yet been run.
- The full dataset and ground-truth mapping are not present in this checkout. Dataset/label/CWE verification is blocked.
- FindSecBugs executable and sample-keyed result data are not present/configured. SAST pilot validation is blocked.
- No pilot request was made because dataset and ground-truth prerequisites are unmet.

## Final readiness decision

A passing unit-test suite is not sufficient by itself. Confirm data integrity, prompt integrity, scenario completeness, and evaluation correctness before declaring the experiment ready.