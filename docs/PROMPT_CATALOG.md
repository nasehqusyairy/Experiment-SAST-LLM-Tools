# Prompt Catalog

## 1. Purpose

This document is the authoritative registry of prompt configurations used in the SAST–LLM benchmark.

It defines:
- The five prompt strategies used in the experiment.
- The source and adaptation status of each strategy.
- The SAST condition permitted for each prompt.
- The input placeholders and output requirements.
- The rules for preserving prompt reproducibility.

**Important:** A prompt strategy and a SAST condition are separate experimental dimensions. However, not every strategy is evaluated under every SAST condition.

## 2. Prompt Configuration Registry

Each row below represents one valid prompt configuration. The `Prompt ID` identifies the strategy, while `SAST Condition` specifies whether FindSecBugs findings are supplied to the LLM.

| Configuration ID | Prompt ID | Source | SAST Condition | Description |
|---|---|---|---|---|
| `baseline-1` | `baseline-1` | Ciavatta et al. (source evidence limited) | `none` | Repository-authored LLM-only operational adaptation; not verified as an exact paper reproduction. |
| `baseline-2` | `baseline-2` | Ciavatta et al. (source evidence limited) | `findsecbugs` | Repository-authored LLM + FindSecBugs operational adaptation; not verified as an exact paper reproduction. |
| `zero-shot-none` | `zero-shot` | Munson et al. | `none` | Zero-Shot strategy adapted to analyze source code without SAST findings. |
| `zero-shot-findsecbugs` | `zero-shot` | Munson et al. | `findsecbugs` | Zero-Shot strategy adapted to use relevant FindSecBugs findings instead of the original paper's SAST context. |
| `cot-none` | `cot` | Munson et al. | `none` | Chain-of-Thought strategy adapted to analyze source code without SAST findings. |
| `cot-findsecbugs` | `cot` | Munson et al. | `findsecbugs` | Chain-of-Thought strategy adapted to use relevant FindSecBugs findings. |
| `tot-none` | `tot` | Munson et al. | `none` | Tree-of-Thoughts strategy adapted to analyze source code without SAST findings. |
| `tot-findsecbugs` | `tot` | Munson et al. | `findsecbugs` | Tree-of-Thoughts strategy adapted to use relevant FindSecBugs findings. |

### Interpretation

- `baseline-1` is evaluated **only without SAST findings**.
- `baseline-2` is evaluated **only with FindSecBugs findings**.
- `zero-shot`, `cot`, and `tot` are each evaluated under **both** `none` and `findsecbugs`.
- The two Ciavatta baselines retain their intended definitions; they must not be silently redefined as paired conditions.
- The Munson configurations using FindSecBugs are adaptations of the original study, which used Semgrep-related static-analysis results. They must not be described as exact reproductions of the original SAST setup.

## 3. Prompt Sources and Adaptation Status

| Prompt ID | Method | Source | Reproduction rule |
|---|---|---|---|
| `baseline-1` | LLM-only baseline | Ciavatta et al., §2.4/Table 5, printed p. 7 | Operational adaptation using repository-authored prompt material; exact source baseline wording/procedure not verified. |
| `baseline-2` | LLM + SAST baseline | Ciavatta et al., §2.4/Table 5, printed p. 7 | Operational adaptation using repository-authored prompt material; exact source baseline wording/procedure not verified. |
| `zero-shot` | Zero-Shot (ZS) | Munson et al., Figure 2, printed p. 27 | Figure wording preserved in `prompts/zero_shot.txt`; no-SAST and FindSecBugs variants are adaptations. |
| `cot` | Chain of Thought (CoT) | Munson et al., Figure 4, printed p. 28 | Figure wording preserved in `prompts/cot.txt`; no-SAST and FindSecBugs variants are adaptations. |
| `tot` | Tree of Thoughts (ToT) | Munson et al., Figure 3, printed p. 27 | Figure wording preserved in `prompts/tot.txt`; no-SAST and FindSecBugs variants are adaptations. |

### Verified source record and implementation status

The Munson reference is *With a Little Help from My (LLM) Friends: Enhancing Static Analysis with LLMs to Detect Software Vulnerabilities*, IEEE/ACM LLM4Code 2025. The prompt figures are on printed page 27: Zero-Shot Figure 2, ToT Figure 3; CoT is Figure 4 on printed page 28. Section III.A describes the experiment prompts. It explicitly says that the CWE name in the prompt corresponds to the test case's ground-truth CWE. This project therefore performs **CWE-targeted vulnerability detection**: the target CWE is supplied as task context, but the vulnerable/benign label is never supplied. A missing or ambiguous CWE mapping blocks that sample rather than being guessed.

The source figures contain: (a) a Zero-Shot question asking whether the code contains the named CWE, with an optional system instruction; (b) ToT instructions to imagine three experts, work stepwise, pass/leave incorrect paths, re-evaluate using information from a static-analysis tool, and select the best final decision; and (c) a CoT instruction to consider whether the named CWE is present, with a stepwise analysis and static-analysis results. The diagrams label inputs “Code Snippet” and “SAST Results.” The Munson prompts retain the target-CWE context in both conditions. `none` removes only SAST-dependent wording and context; `findsecbugs` replaces the paper's Semgrep/SARIF context with the current sample's FindSecBugs findings. These are explicit adaptations, not exact reproductions of the original experiment/tool setup.

The Ciavatta reference is *Integration of Large Language Models (LLMs) and Static Analysis for Improving the Efficacy of Security Vulnerability Detection in Source Code*. Section 2.4 and Table 5 (printed page 7) verify general prompt techniques, including “You are a security assistant,” instruction framing, category context, FindSecBugs context, structured output, and internal/external response instructions. The paper does not establish the project labels `baseline-1` and `baseline-2` as named, fully specified procedures in the text evidence verified here. Accordingly, both are **operational adaptations**, not claimed exact reproductions: `baseline-1` uses repository-authored LLM-only prompt material; `baseline-2` uses repository-authored FindSecBugs-assisted prompt material. Exact paper-specific baseline wording/procedure remains an evidence gap. The pre-existing templates in `Prompt/FirstPrompt.py` and `Prompt/SecondPrompt.py` are repository-authored; they are not presented as verbatim paper quotations.

Munson Figure prompts elicit stepwise reasoning (and ToT explicitly asks experts to share intermediate steps). The runtime adaptations instead instruct ToT experts to evaluate privately and return only the final decision and concise evidence summary; the version-2 ToT files record this change. All adapted Munson variants use the common JSON contract and prohibit hidden chain-of-thought disclosure. These output-contract/safety changes are documented adaptations, not exact methodological reproductions.

The five version-controlled files under `prompts/` are the runtime source templates. `prompts/munson_adaptations/` contains condition-specific, versioned wording for removing or replacing SAST context; no runtime rewriting of the source files occurs. `experiment_config.json` maps the five source templates to exactly the eight valid configurations.

Do not label a prompt as an exact reproduction unless its wording and procedure have been checked against the original paper. If the source wording is unavailable or unclear, document the implementation as an adaptation rather than presenting reconstructed wording as a verbatim quotation.

## 4. SAST Condition Definitions

### `none`

The LLM receives the Java source code and the applicable vulnerability-analysis instructions, but **no FindSecBugs findings**.

Requirements:
- Do not include findings, severity values, source-analysis messages, or other output generated by FindSecBugs.
- Do not leak ground-truth labels or expected outcomes.
- Do not leave instructions that incorrectly imply that SAST findings are present.
- Document any changes to the original prompt that are necessary to support this condition.

### `findsecbugs`

The LLM receives the Java source code and relevant FindSecBugs findings for the same benchmark test case.

Requirements:
- Run FindSecBugs using the documented analysis procedure.
- Associate findings with the correct Java test case.
- Supply only the findings intended for that test case.
- Represent an empty finding result explicitly as no findings, rather than borrowing findings from another sample.
- Do not supply the benchmark's expected vulnerable/benign label.
- Preserve enough metadata to trace each supplied finding to its original SAST output.

A missing or failed SAST execution must not automatically be treated as a successful execution with zero findings. Record such cases separately and handle them according to the experiment's validation rules.

## 5. Prompt Input Placeholders

Use consistent placeholder names where compatible with the original prompt.

| Placeholder | Meaning |
|---|---|
| `{JAVA_SOURCE_CODE}` | Source code for the current OWASP Benchmark Java test case. |
| `{CWE_NAME}` | Vulnerability category provided as task context when required by the prompt. |
| `{SAST_CONTEXT}` | Relevant FindSecBugs findings for the current test case. |

The implementation may use different internal placeholder names if required by the existing repository, but the mapping must be explicit and tested.

For the `none` condition, `{SAST_CONTEXT}` must not inject actual findings. The prompt renderer must also ensure that no leftover template instructions refer to findings that were not supplied.

The dataset's expected label must never be included in the model input.

## 6. Output Requirements

Use a consistent machine-readable classification schema across configurations wherever feasible. For example:

```json
{
  "vulnerable": true,
  "cwe": "CWE-89",
  "line": 12,
  "reason": "Brief explanation based on the supplied code and permitted evidence."
}
```

This schema is an implementation contract, not a claim that the cited papers used this exact JSON structure.

Requirements:
- Validate the model output before evaluation.
- Preserve the raw model response.
- Record parsing failures explicitly; do not silently convert malformed responses into benign classifications.
- Store any normalized classification separately from the raw response.
- Store a brief rationale or evidence summary, not hidden chain-of-thought content.
- Apply the same interpretation rules to all compared configurations wherever possible.

For the Ciavatta-derived operational baselines, the repository-authored response formats differ: `baseline-1` asks for Q1–Q4; `baseline-2` asks for Q1–Q5. The runner requests JSON mode and accepts JSON objects with those Q-fields; the parser enforces Q1–Q4 for `baseline-1`, Q1–Q5 for `baseline-2`, validates the allowed Q2 category and Q5/Q1 consistency, then normalizes into `{vulnerable,cwe,line,reason}` using Q1/Q3/Q4. Q5 is a model-generated TP/FP answer, not ground truth; the evaluator never exposes expected labels. Legacy Q-line text parsing is supported for the same fields. The wording's “only three questions” phrase conflicts with its enumerated questions; the source templates are preserved, and the runtime contract is the enumerated Q-fields. Raw responses remain untouched. None of this makes the baselines paper-exact.

If a source baseline requires a different original output format, document the conversion into the common evaluation schema and retain the original response.

## 7. Model and Thinking Settings

Model selection and thinking settings are experiment dimensions, not prompt IDs.

The primary model set is:
- `deepseek-coder:6.7b`
- `qwen2.5-coder:7b`
- `gemma4:e4b`

For Gemma 4 E4B, a thinking-enabled scenario may be added only if the installed model and runtime support the setting.

Requirements:
- Record the exact model tag and relevant runtime/generation settings.
- Keep normal and thinking-enabled Gemma runs distinguishable.
- Do not silently fall back to another thinking setting if the requested configuration is unsupported.
- Do not duplicate prompt definitions merely to represent a model's thinking mode.

## 8. Reproducibility and Versioning Rules

1. Keep each prompt template in a dedicated, version-controlled file or module.
2. Record the source paper, figure or section where applicable, and whether the wording is verbatim, reconstructed, or adapted.
3. Preserve the approved wording; do not silently rewrite prompts.
4. Record any change to prompt wording, input structure, SAST context, or output instructions.
5. Give meaningful prompt changes a new version identifier.
6. Keep prompt strategy, SAST condition, model identity, and thinking settings as separate metadata fields.
7. Include the configuration ID in result records and resume keys.
8. Never use ground-truth labels as model input.
9. Test prompt rendering for every configuration before running the full dataset.
10. Do not start the full benchmark automatically as part of development or validation.

## 9. Expected Configuration Coverage

The five strategies produce **eight valid prompt configurations**:

- Two Ciavatta reference configurations: `baseline-1` and `baseline-2`.
- Three Munson strategies under `none`: `zero-shot-none`, `cot-none`, and `tot-none`.
- Three Munson strategies under `findsecbugs`: `zero-shot-findsecbugs`, `cot-findsecbugs`, and `tot-findsecbugs`.

With three primary models, these configurations yield 24 model–prompt–SAST combinations before any additional thinking-enabled scenario, exclusions, or failed runs.

The experiment manager must derive its run plan from the valid configuration registry rather than assuming that every prompt can be combined with every SAST condition.
