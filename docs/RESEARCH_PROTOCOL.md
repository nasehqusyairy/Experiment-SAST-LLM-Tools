# Research Protocol

## Objective

Evaluate how prompting strategies affect LLM-based Java vulnerability detection under LLM-only and LLM + FindSecBugs conditions.

## Dataset

Use OWASP Benchmark Java v1.2 with 2,740 test cases and the corresponding ground-truth labels. Dataset files and labels must be validated before full experiments.

## Models

- `deepseek-coder:6.7b`
- `qwen2.5-coder:7b`
- `gemma4:e4b`

Add a separate thinking-enabled scenario for Gemma, but only after verifying support in the installed Ollama version and model.

## Prompt strategies

- `baseline-1`: Ciavatta et al., LLM-only reference prompt.
- `baseline-2`: Ciavatta et al., SAST-assisted reference prompt.
- `zero-shot`: Munson et al., Zero-Shot.
- `tot`: Munson et al., Tree of Thoughts.
- `cot`: Munson et al., Chain of Thought.

The exact source wording and every adaptation must be documented in the prompt catalog.

For Munson Zero-Shot, CoT, and ToT, supply the target CWE as task context for the sample, consistent with §III.A and Figures 2–4 of the Munson paper. This study is CWE-targeted vulnerability detection. Do not supply the vulnerable/benign ground-truth outcome, a proxy for it, or any label-derived statement. Use the same verified CWE in paired `none` and `findsecbugs` runs. If the sample-to-CWE mapping is absent or ambiguous, record a data-validation failure and do not guess.

The Ciavatta baseline IDs are operational adaptations. Do not claim exact reproduction: the verified source evidence in §2.4/Table 5 supports prompt techniques, but does not establish these project IDs and complete prompt procedures as exact named baselines. Distinguish paper-derived techniques, repository-authored text, reconstruction, and experimental adaptations in the catalog.

## SAST conditions

The primary strategies (`zero-shot`, `tot`, and `cot`) must support both:

- `none`: no SAST output supplied to the model.
- `findsecbugs`: corresponding precomputed FindSecBugs results supplied to the model.

Use the same SAST results across matched scenarios. Never fabricate missing findings.

## Evaluation

Join predictions with ground truth by stable test-case identifier. Report TP, FP, TN, FN, precision, recall, F1, FPR, TNR, balanced accuracy, MCC, and accuracy.

Keep raw outputs and per-sample predictions. Report missing predictions, invalid responses, and failed calls separately.

## Reproducibility

Record model and runtime versions, prompt ID and version, SAST condition, thinking setting, generation parameters, dataset identity, timestamps, and software configuration.

Do not run the full experiment matrix automatically during setup or development.