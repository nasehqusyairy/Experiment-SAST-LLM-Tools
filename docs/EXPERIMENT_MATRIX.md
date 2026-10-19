# Experiment Matrix

## Standard models

- `deepseek-coder:6.7b`
- `qwen2.5-coder:7b`
- `gemma4:e4b`

## Prompt configurations

- `baseline-1`
- `baseline-2`
- `zero-shot`
- `tot`
- `cot`

## Conditions

The primary prompt strategies `zero-shot`, `tot`, and `cot` must run with both `none` and `findsecbugs`.

The Ciavatta baselines must follow their documented definitions. Do not create invalid or duplicate baseline combinations merely to fill a Cartesian product.

## Gemma thinking mode

Treat standard Gemma and Gemma with thinking enabled as separate configurations. Verify support and record the actual runtime setting.

The manager adds distinct optional Gemma thinking scenario identities only when `/api/show` verifies support, and sends `think: false` for standard mode when the model supports an explicit thinking control. Runtime/model availability is checked live; no current environment claim is made by this document. Thinking inference is opt-in and has not been authorized as part of audit validation.

## Scenario identity

Every scenario ID must include, or map unambiguously to:

- Model
- Prompt ID and version
- SAST condition
- Thinking setting
- Generation configuration
- Dataset identity

Generate the final scenario list programmatically from a validated registry. Report valid, blocked, completed, and pending scenarios. Do not assume the final count before applying the baseline and Gemma-specific rules.