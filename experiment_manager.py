from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "experiment_config.json"
DEFAULT_STATE = ROOT / "experiment_state.sqlite3"
DEFAULT_OUTPUT = ROOT / "experiment_runs"
FORBIDDEN_LABEL_TERMS = ("ground_truth", "ground-truth", "vulnerable_label", "expected_label")


def load_registry(path: Path = CONFIG_PATH) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    prompts = data.get("prompts", {})
    valid = {"baseline-1", "baseline-2", "zero-shot-none", "zero-shot-findsecbugs", "cot-none", "cot-findsecbugs", "tot-none", "tot-findsecbugs"}
    if set(prompts) != valid:
        raise ValueError("Configuration IDs do not match the approved eight configurations")
    for config_id, config in prompts.items():
        if config.get("sast") not in {"none", "findsecbugs"}:
            raise ValueError(f"Invalid SAST condition for {config_id}")
        path_to_template = template_path(config, path.parent)
        if not path_to_template.is_file():
            raise ValueError(f"Missing template for {config_id}: {config.get('template')}")
        text = path_to_template.read_text(encoding="utf-8")
        required = {"JAVA_SOURCE_CODE"}
        if config["prompt_id"] in {"zero-shot", "cot", "tot"} or config_id == "baseline-2":
            required.add("CWE_NAME")
        if config["sast"] == "findsecbugs":
            required.add("SAST_CONTEXT")
        missing = required - _field_names(text)
        if missing:
            raise ValueError(f"{config_id} template missing placeholders: {sorted(missing)}")
    return prompts


def _field_names(template: str) -> set[str]:
    import string
    return {field for _, field, _, _ in string.Formatter().parse(template) if field}


def template_path(config: dict[str, Any], base: Path = ROOT) -> Path:
    return (base / config["template"]).resolve()


def render_prompt(config: dict[str, Any], java_source: str, cwe_name: str, sast_context: str, *, ground_truth: Any = None, base: Path = ROOT) -> str:
    if ground_truth is not None:
        raise ValueError("Ground-truth vulnerable/benign outcome is forbidden in model prompts")
    if not cwe_name or not cwe_name.strip():
        raise ValueError("Target CWE is required; refusing to guess")
    if config["sast"] == "none":
        sast_context = ""
    elif not sast_context.strip():
        raise ValueError("FindSecBugs results are required for this configuration; empty results must be explicit")
    template = template_path(config, base).read_text(encoding="utf-8")
    values = {"JAVA_SOURCE_CODE": java_source, "CWE_NAME": cwe_name, "SAST_CONTEXT": sast_context, "SYSTEM_INSTRUCTIONS": "", "ADDITIONAL_INSTRUCTIONS": ""}
    rendered = template.format_map(_StrictFormat(values))
    lowered = rendered.lower()
    for term in FORBIDDEN_LABEL_TERMS:
        if term in lowered:
            raise ValueError(f"Forbidden ground-truth marker found in rendered prompt: {term}")
    return rendered


class _StrictFormat(dict):
    def __missing__(self, key: str) -> str:
        raise ValueError(f"Unsupported prompt placeholder: {{{key}}}")


def parse_prediction(raw: str) -> dict[str, Any]:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        # Legacy repository prompts use Q1-Q4 rather than the common JSON contract.
        import re
        q1 = re.search(r"(?im)^\s*Q1\s*:\s*(TRUE|FALSE)\b", raw)
        q3 = re.search(r"(?im)^\s*Q3\s*:\s*(\d+)", raw)
        q4 = re.search(r"(?im)^\s*Q4\s*:\s*(CWE-?\d+|\d+)", raw)
        if not q1:
            raise ValueError("Invalid JSON response and no valid legacy Q1 classification")
        q4_value = q4.group(1) if q4 else ""
        cwe = f"CWE-{q4_value}" if q4_value.isdigit() else q4_value
        obj = {"vulnerable": q1.group(1).upper() == "TRUE", "cwe": cwe, "line": int(q3.group(1)) if q3 else None, "reason": ""}
    if isinstance(obj, dict) and "vulnerable" not in obj and "Q1" in obj:
        q1_value = obj["Q1"]
        if isinstance(q1_value, bool):
            vulnerable = q1_value
        elif isinstance(q1_value, str) and q1_value.strip().upper() in {"TRUE", "FALSE"}:
            vulnerable = q1_value.strip().upper() == "TRUE"
        else:
            raise ValueError("Legacy Q1 must be a boolean or TRUE/FALSE string")
        q4 = obj.get("Q4", "")
        if isinstance(q4, int) and not isinstance(q4, bool):
            cwe = f"CWE-{q4}"
        elif isinstance(q4, str) and q4.strip().isdigit():
            cwe = f"CWE-{q4.strip()}"
        else:
            cwe = str(q4 or obj.get("Q2", ""))
        q3 = obj.get("Q3")
        obj = {"vulnerable": vulnerable, "cwe": cwe, "line": q3, "reason": ""}
    if not isinstance(obj, dict) or not isinstance(obj.get("vulnerable"), bool):
        raise ValueError("Response must be a JSON object with boolean 'vulnerable'")
    if not isinstance(obj.get("cwe"), str):
        raise ValueError("Response must include string 'cwe'")
    line = obj.get("line")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool)):
        raise ValueError("'line' must be an integer or null")
    reason = obj.get("reason", "")
    if not isinstance(reason, str):
        raise ValueError("'reason' must be a string")
    return {"vulnerable": obj["vulnerable"], "cwe": obj["cwe"], "line": line, "reason": reason}


def calculate_metrics(truth: list[bool], predictions: list[bool]) -> dict[str, float | int]:
    if len(truth) != len(predictions) or not truth:
        raise ValueError("Truth and predictions must have equal non-zero lengths")
    tp = sum(t and p for t, p in zip(truth, predictions))
    tn = sum(not t and not p for t, p in zip(truth, predictions))
    fp = sum(not t and p for t, p in zip(truth, predictions))
    fn = sum(t and not p for t, p in zip(truth, predictions))
    div = lambda n, d: n / d if d else 0.0
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    f1 = div(2 * precision * recall, precision + recall)
    tnr, fpr = div(tn, tn + fp), div(fp, fp + tn)
    mcc_den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1, "fpr": fpr, "tnr": tnr, "balanced_accuracy": (recall + tnr) / 2, "mcc": div(tp * tn - fp * fn, mcc_den), "accuracy": div(tp + tn, len(truth))}


def write_raw_output(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(text)


class StateStore:
    def __init__(self, path: Path = DEFAULT_STATE):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS tasks (task_id TEXT PRIMARY KEY, status TEXT NOT NULL, detail TEXT, updated_at TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS scenarios (scenario_id TEXT PRIMARY KEY, model TEXT NOT NULL, config_id TEXT NOT NULL, status TEXT NOT NULL, detail TEXT, updated_at TEXT NOT NULL)")
        self.db.commit()

    def set_task(self, task_id: str, status: str, detail: str = "") -> None:
        self.db.execute("INSERT INTO tasks VALUES (?, ?, ?, ?) ON CONFLICT(task_id) DO UPDATE SET status=excluded.status, detail=excluded.detail, updated_at=excluded.updated_at", (task_id, status, detail, _now()))
        self.db.commit()

    def task_status(self, task_id: str) -> str | None:
        row = self.db.execute("SELECT status FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return row[0] if row else None

    def ensure_setup_tasks(self) -> None:
        tasks = {
            "dataset": "Validate OWASP Benchmark Java v1.2 identity and 2,740 samples",
            "ground_truth": "Validate vulnerable/benign labels and target-CWE mapping",
            "prompts": "Validate prompt files, versions, and configuration mapping",
            "ollama": "Verify local Ollama endpoint and runtime version",
            "models": "Verify all required Ollama model tags",
            "findsecbugs": "Verify FindSecBugs version and same-sample result mapping",
            "gemma_thinking": "Verify Gemma thinking-mode support (optional scenario)",
            "pilot_review": "Run and manually inspect one approved pilot sample",
        }
        for task_id, detail in tasks.items():
            if self.task_status(task_id) is None:
                self.set_task(task_id, "pending", detail)

    def ensure_scenarios(self, registry: dict[str, dict[str, Any]], models: list[str], thinking_models: list[str] | tuple[str, ...] = ()) -> None:
        for scenario in build_scenarios(registry, models, thinking_models):
            exists = self.db.execute("SELECT 1 FROM scenarios WHERE scenario_id=?", (scenario["scenario_id"],)).fetchone()
            if not exists:
                self.set_scenario(scenario["scenario_id"], scenario["model"], scenario["config_id"], "pending", "")

    def set_scenario(self, scenario_id: str, model: str, config_id: str, status: str, detail: str = "") -> None:
        self.db.execute("INSERT INTO scenarios VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(scenario_id) DO UPDATE SET status=excluded.status, detail=excluded.detail, updated_at=excluded.updated_at", (scenario_id, model, config_id, status, detail, _now()))
        self.db.commit()

    def rows(self, table: str) -> list[tuple]:
        if table not in {"tasks", "scenarios"}:
            raise ValueError("invalid table")
        return self.db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()

    def close(self) -> None:
        self.db.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_dataset(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"sample_id", "java_source", "target_cwe", "vulnerable"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"Dataset CSV must contain columns: {', '.join(sorted(required))}")
        for row in reader:
            sample_id = row["sample_id"].strip()
            if not sample_id or sample_id in rows:
                raise ValueError(f"Missing or duplicate sample_id: {sample_id!r}")
            if not row["target_cwe"].strip() or not re.fullmatch(r"CWE-\d+", row["target_cwe"].strip(), flags=re.IGNORECASE):
                raise ValueError(f"Missing or non-canonical target CWE for sample {sample_id}; expected CWE-<number>")
            label = row["vulnerable"].strip().lower()
            if label not in {"true", "false", "1", "0", "yes", "no"}:
                raise ValueError(f"Invalid vulnerable label for {sample_id}")
            row["_label"] = label in {"true", "1", "yes"}
            rows[sample_id] = row
    return rows


def load_sast(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or any(not isinstance(v, (str, list, dict)) for v in data.values()):
        raise ValueError("FindSecBugs JSON must map sample IDs to findings")
    return {str(k): (v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, sort_keys=True)) for k, v in data.items()}


def ollama_models(endpoint: str = "http://localhost:11434") -> set[str]:
    with urllib.request.urlopen(endpoint.rstrip("/") + "/api/tags", timeout=4) as response:
        return {m["name"] for m in json.load(response).get("models", [])}


def ollama_version(endpoint: str = "http://localhost:11434") -> str:
    with urllib.request.urlopen(endpoint.rstrip("/") + "/api/version", timeout=5) as response:
        return str(json.load(response).get("version", "unknown"))


def ollama_model_info(model: str, endpoint: str = "http://localhost:11434") -> dict[str, Any]:
    request = urllib.request.Request(endpoint.rstrip("/") + "/api/show", data=json.dumps({"model": model}).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def call_ollama(model: str, prompt: str, generation: dict[str, Any], endpoint: str = "http://localhost:11434", thinking: bool = False) -> str:
    payload = {"model": model, "prompt": prompt, "stream": False, "format": "json", "options": dict(generation)}
    if thinking:
        payload["think"] = True
    request = urllib.request.Request(endpoint.rstrip("/") + "/api/generate", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.load(response).get("response", "")


def build_scenarios(registry: dict[str, dict[str, Any]], models: list[str], thinking_models: list[str] | tuple[str, ...] = ()) -> list[dict[str, str]]:
    scenarios = [{"scenario_id": f"{model}__{config_id}__standard", "model": model, "config_id": config_id, "thinking": "standard"} for model in models for config_id in registry]
    scenarios.extend({"scenario_id": f"{model}__{config_id}__thinking", "model": model, "config_id": config_id, "thinking": "enabled"} for model in thinking_models if model in models for config_id in registry)
    return scenarios


def dashboard(state: StateStore, registry: dict[str, dict[str, Any]]) -> None:
    tasks = state.rows("tasks")
    scenarios = state.rows("scenarios")
    task_counts = {status: sum(row[1] == status for row in tasks) for status in ("pending", "running", "completed", "failed", "blocked")}
    scenario_counts = {status: sum(row[3] == status for row in scenarios) for status in ("pending", "running", "completed", "failed", "blocked")}
    db_path = state.db.execute("PRAGMA database_list").fetchone()[2]
    print(f"Prompt configurations: {len(registry)} valid")
    print(f"Tasks ({task_counts}): {tasks or 'none recorded'}")
    print(f"Scenarios ({scenario_counts}): {scenarios or 'none recorded'}")
    print(f"State database: {db_path}")
    print(f"Raw output root: {DEFAULT_OUTPUT}")


def evaluate_scenario(dataset_path: Path, scenario_dir: Path, summary_path: Path) -> dict[str, Any]:
    data = load_dataset(dataset_path)
    predictions: dict[str, bool] = {}
    invalid = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(scenario_dir.glob("*.invalid.json"))]
    for path in sorted(scenario_dir.glob("*.prediction.json")):
        obj = json.loads(path.read_text(encoding="utf-8"))
        sample_id = obj.get("sample_id")
        if sample_id not in data or sample_id in predictions:
            invalid.append({"file": str(path), "error": "unknown or duplicate sample_id"})
            continue
        if not isinstance(obj.get("vulnerable"), bool):
            invalid.append({"file": str(path), "error": "missing/invalid vulnerable field"})
            continue
        predictions[sample_id] = obj["vulnerable"]
    failed_calls = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(scenario_dir.glob("*.failed.json"))]
    comparable = sorted(set(data) & set(predictions))
    metrics = calculate_metrics([data[sid]["_label"] for sid in comparable], [predictions[sid] for sid in comparable]) if comparable else None
    raw_artifacts = [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(scenario_dir.glob("*.raw.txt"))]
    metadata_paths = sorted(scenario_dir.glob("*.metadata.json"))
    run_metadata = [json.loads(path.read_text(encoding="utf-8")) for path in metadata_paths]
    report = {
        "scenario": scenario_dir.name,
        "run_metadata": run_metadata,
        "raw_artifacts": raw_artifacts,
        "dataset": str(dataset_path),
        "dataset_samples": len(data),
        "prediction_count": len(predictions),
        "evaluated_count": len(comparable),
        "missing_predictions": sorted(set(data) - set(predictions)),
        "invalid_responses": invalid,
        "failed_calls": failed_calls,
        "metrics": metrics,
        "generated_at_utc": _now(),
        "raw_output_directory": str(scenario_dir),
        "prediction_files_are_normalized_not_raw": True,
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write(chr(10))
    return report


def run_one(args: argparse.Namespace, state: StateStore, registry: dict[str, dict[str, Any]]) -> int:
    if args.config not in registry:
        raise ValueError(f"Unknown configuration: {args.config}")
    if args.model not in json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["models"]:
        raise ValueError(f"Model is not in the approved experiment matrix: {args.model}")
    required_tasks = ["dataset", "ground_truth", "prompts", "ollama", "models"]
    if registry[args.config]["sast"] == "findsecbugs":
        required_tasks.append("findsecbugs")
    if args.thinking:
        required_tasks.append("gemma_thinking")
    incomplete = [task_id for task_id in required_tasks if state.task_status(task_id) != "completed"]
    if incomplete:
        raise ValueError(f"Prerequisite setup tasks must be explicitly validated and marked completed: {', '.join(incomplete)}")
    data = load_dataset(Path(args.dataset))
    expected_count = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["dataset"]["required_samples"]
    if len(data) != expected_count:
        raise ValueError(f"Dataset contains {len(data)} unique records; expected {expected_count} for OWASP Benchmark Java v1.2")
    if args.sample not in data:
        raise ValueError(f"Sample not found: {args.sample}")
    sample, config = data[args.sample], registry[args.config]
    installed_models = ollama_models(args.endpoint)
    if args.model not in installed_models:
        raise ValueError(f"Ollama model tag is not installed: {args.model}")
    model_info = ollama_model_info(args.model, args.endpoint)
    capabilities = model_info.get("capabilities", [])
    if args.thinking and (args.model != "gemma4:e4b" or "thinking" not in capabilities):
        raise ValueError("Thinking mode requires gemma4:e4b and Ollama /api/show capability 'thinking'")
    runtime_version = ollama_version(args.endpoint)
    sast = ""
    if config["sast"] == "findsecbugs":
        if not args.findsecbugs:
            raise ValueError("--findsecbugs JSON is required for this configuration")
        findings = load_sast(Path(args.findsecbugs))
        if args.sample not in findings:
            raise ValueError(f"No FindSecBugs result for sample {args.sample}; refusing to borrow or assume empty findings")
        sast = findings[args.sample]
    prompt = render_prompt(config, sample["java_source"], sample["target_cwe"], sast)
    scenario_id = args.scenario_id or f"{args.model}__{args.config}__{'thinking' if args.thinking else 'standard'}"
    state.set_scenario(scenario_id, args.model, args.config, "running")
    outdir = Path(args.output_dir) / scenario_id
    sample_key = hashlib.sha256(args.sample.encode()).hexdigest()[:12]
    raw_path, input_path, pred_path = (outdir / f"{sample_key}.{suffix}" for suffix in ("raw.txt", "input.txt", "prediction.json"))
    failed_path = outdir / f"{sample_key}.failed.json"
    invalid_path = outdir / f"{sample_key}.invalid.json"
    manifest_path = outdir / f"{sample_key}.metadata.json"
    existing = [path.exists() for path in (raw_path, input_path, pred_path, failed_path, invalid_path, manifest_path)]
    if all(path.exists() for path in (raw_path, input_path, pred_path, manifest_path)) and not failed_path.exists():
        state.set_scenario(scenario_id, args.model, args.config, "completed", f"resumed; existing sample output preserved: {raw_path}")
        print(f"Already completed {args.sample}; safely skipping existing output")
        return 0
    if any(existing):
        state.set_scenario(scenario_id, args.model, args.config, "blocked", "partial output exists; use a new scenario ID after inspection")
        raise FileExistsError(f"Partial output exists for {scenario_id}/{args.sample}; refusing unsafe resume")
    outdir.mkdir(parents=True, exist_ok=True)
    input_path.write_text(prompt, encoding="utf-8")
    generation = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["generation"]
    metadata = {
        "scenario_id": scenario_id, "sample_id": args.sample, "model_tag": args.model,
        "model_details": model_info.get("details", {}), "model_capabilities": capabilities,
        "ollama_runtime_version": runtime_version,
        "config_id": args.config, "prompt_id": config["prompt_id"], "prompt_version": config["version"],
        "source_status": config["source_status"], "sast_condition": config["sast"],
        "thinking": bool(args.thinking), "generation": generation,
        "dataset_path": str(Path(args.dataset).resolve()),
        "dataset_identity": "OWASP Benchmark Java v1.2",
        "dataset_samples": len(data),
        "dataset_sha256": hashlib.sha256(Path(args.dataset).read_bytes()).hexdigest(),
        "rendered_prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "raw_response_path": str(raw_path), "started_at_utc": _now(),
    }
    if args.findsecbugs:
        metadata["findsecbugs_path"] = str(Path(args.findsecbugs).resolve())
        metadata["findsecbugs_sha256"] = hashlib.sha256(Path(args.findsecbugs).read_bytes()).hexdigest()
    with manifest_path.open("x", encoding="utf-8") as stream:
        json.dump(metadata, stream, indent=2)
        stream.write(chr(10))
    try:
        raw = call_ollama(args.model, prompt, generation, endpoint=args.endpoint, thinking=args.thinking)
        write_raw_output(raw_path, raw)
        try:
            parsed = parse_prediction(raw)
        except ValueError as exc:
            with invalid_path.open("x", encoding="utf-8") as stream:
                json.dump({"sample_id": args.sample, "error": str(exc), "raw_response_path": str(raw_path)}, stream, indent=2)
                stream.write(chr(10))
            raise
        pred_path.write_text(json.dumps({"sample_id": args.sample, **parsed}, indent=2) + chr(10), encoding="utf-8")
        state.set_scenario(scenario_id, args.model, args.config, "completed", str(raw_path))
        print(f"Completed selected sample {args.sample}; raw response: {raw_path}")
        return 0
    except Exception as exc:
        if not raw_path.exists() and not failed_path.exists():
            with failed_path.open("x", encoding="utf-8") as stream:
                json.dump({"sample_id": args.sample, "error": str(exc), "failed_at_utc": _now()}, stream, indent=2)
                stream.write(chr(10))
        state.set_scenario(scenario_id, args.model, args.config, "failed", str(exc))
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Persistent, explicit-selection OWASP SAST–LLM experiment manager")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Show persistent tasks and scenario state")
    sub.add_parser("validate", help="Validate prompt registry and local Ollama/model prerequisites")
    task = sub.add_parser("task", help="Record a setup task")
    task.add_argument("task_id"); task.add_argument("status", choices=["pending", "running", "completed", "blocked", "failed"]); task.add_argument("--detail", default="")
    run = sub.add_parser("run", help="Run exactly one selected sample/configuration")
    run.add_argument("--config", required=True); run.add_argument("--model", required=True); run.add_argument("--dataset", required=True); run.add_argument("--sample", required=True); run.add_argument("--findsecbugs"); run.add_argument("--scenario-id"); run.add_argument("--output-dir", default=str(DEFAULT_OUTPUT)); run.add_argument("--endpoint", default="http://localhost:11434"); run.add_argument("--thinking", action="store_true")
    summary = sub.add_parser("summary", help="Evaluate one scenario without overwriting prior summaries")
    summary.add_argument("--dataset", required=True); summary.add_argument("--scenario-dir", required=True); summary.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    state = StateStore(args.state)
    try:
        registry = load_registry()
        models = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["models"]
        state.ensure_setup_tasks()
        state.ensure_scenarios(registry, models)
        if args.command == "status":
            dashboard(state, registry); return 0
        if args.command == "task":
            state.set_task(args.task_id, args.status, args.detail); dashboard(state, registry); return 0
        if args.command == "validate":
            print(f"Prompt registry: valid ({len(registry)} configs)")
            try:
                tags = ollama_models()
                print(f"Ollama: available; version={ollama_version()}; installed models: {', '.join(sorted(tags))}")
                thinking_supported = False
                for model in json.loads(CONFIG_PATH.read_text())["models"]:
                    if model not in tags:
                        print(f"Model {model}: MISSING")
                        continue
                    info = ollama_model_info(model)
                    caps = info.get("capabilities", [])
                    print(f"Model {model}: available; capabilities={caps}")
                    if model == "gemma4:e4b":
                        thinking_supported = "thinking" in caps
                print(f"Gemma thinking capability: {'verified by /api/show' if thinking_supported else 'not verified'}")
                state.set_task("ollama", "completed", "Ollama API tags endpoint reachable")
                missing_models = [model for model in models if model not in tags]
                state.set_task("models", "blocked" if missing_models else "completed", f"missing: {', '.join(missing_models)}" if missing_models else "all required tags are installed")
                if thinking_supported:
                    state.ensure_scenarios(registry, models, ["gemma4:e4b"])
                    state.set_task("gemma_thinking", "completed", "Ollama /api/show reports thinking capability for gemma4:e4b; scenario is opt-in")
                else:
                    state.set_task("gemma_thinking", "blocked", "Ollama /api/show did not confirm thinking capability")
            except Exception as exc:
                state.set_task("ollama", "blocked", str(exc))
                print(f"Ollama: unavailable ({exc})")
            state.set_task("prompts", "completed", "8 configs and all referenced files validated")
            state.set_task("dataset", "blocked", "dataset files not present in repository; provide validated OWASP Benchmark Java v1.2 CSV")
            state.set_task("ground_truth", "blocked", "dataset/labels and target-CWE mapping unavailable for validation")
            state.set_task("findsecbugs", "blocked", "FindSecBugs executable and per-sample results not configured")
            state.set_task("pilot_review", "blocked", "pilot prerequisites incomplete; no model requests made")
            print("Dataset: not bundled; configure and validate a benchmark CSV before running")
            print("FindSecBugs: executable/results not configured; validate externally before SAST scenarios")
            return 0
        if args.command == "run":
            return run_one(args, state, registry)
        if args.command == "summary":
            report = evaluate_scenario(Path(args.dataset), Path(args.scenario_dir), Path(args.output))
            print(json.dumps(report, indent=2))
            return 0
        return 2
    except Exception as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    finally:
        state.close()


if __name__ == "__main__":
    raise SystemExit(main())
