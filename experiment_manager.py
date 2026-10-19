from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sqlite3
import sys
import urllib.parse
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
    expected = {
        "baseline-1": ("baseline-1", "none"),
        "baseline-2": ("baseline-2", "findsecbugs"),
        "zero-shot-none": ("zero-shot", "none"),
        "zero-shot-findsecbugs": ("zero-shot", "findsecbugs"),
        "cot-none": ("cot", "none"),
        "cot-findsecbugs": ("cot", "findsecbugs"),
        "tot-none": ("tot", "none"),
        "tot-findsecbugs": ("tot", "findsecbugs"),
    }
    for config_id, config in prompts.items():
        if (config.get("prompt_id"), config.get("sast")) != expected[config_id]:
            raise ValueError(f"Invalid prompt/SAST mapping for approved configuration {config_id}")
        path_to_template = template_path(config, path.parent)
        if path_to_template != (path.parent / config["template"]).resolve() or not path_to_template.is_relative_to(path.parent.resolve()):
            raise ValueError(f"Template path escapes the repository for {config_id}")
        if not path_to_template.is_file():
            raise ValueError(f"Missing template for {config_id}: {config.get('template')}")
        text = path_to_template.read_text(encoding="utf-8")
        allowed_fields = {"JAVA_SOURCE_CODE", "CWE_NAME", "SAST_CONTEXT", "SYSTEM_INSTRUCTIONS", "ADDITIONAL_INSTRUCTIONS"}
        unsupported = _field_names(text) - allowed_fields
        if unsupported:
            raise ValueError(f"{config_id} template has unsupported/unresolved placeholders: {sorted(unsupported)}")
        required = {"JAVA_SOURCE_CODE"}
        if config["prompt_id"] in {"zero-shot", "cot", "tot"} or config_id == "baseline-2":
            required.add("CWE_NAME")
        if config["sast"] == "findsecbugs":
            required.add("SAST_CONTEXT")
        missing = required - _field_names(text)
        if missing:
            raise ValueError(f"{config_id} template missing placeholders: {sorted(missing)}")
        source = config.get("source_template")
        if source:
            source_path = (path.parent / source).resolve()
            if not source_path.is_relative_to(path.parent.resolve()) or not source_path.is_file():
                raise ValueError(f"{config_id} source template is missing or escapes the repository")
    if data.get("models") != ["deepseek-coder:6.7b", "qwen2.5-coder:7b", "gemma4:e4b"]:
        raise ValueError("Configured model tags differ from the approved experiment model set")
    generation = data.get("generation")
    if not isinstance(generation, dict) or set(generation) != {"temperature", "top_p", "top_k", "repeat_penalty"}:
        raise ValueError("Generation parameters must explicitly define temperature, top_p, top_k and repeat_penalty")
    if any(not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) for value in generation.values()):
        raise ValueError("Generation parameters must be finite numeric values")
    if not 0 <= generation["temperature"] or not 0 < generation["top_p"] <= 1 or not isinstance(generation["top_k"], int) or generation["top_k"] < 1 or generation["repeat_penalty"] <= 0:
        raise ValueError("Generation parameter values are invalid")
    return prompts


def _field_names(template: str) -> set[str]:
    import string
    return {field for _, field, _, _ in string.Formatter().parse(template) if field}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json_strict(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)


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


def parse_prediction(raw: str, config_id: str | None = None) -> dict[str, Any]:
    categories = {"pathtraver", "hash", "trustbound", "crypto", "cmdi", "sqli", "weakrand", "ldapi", "xss", "securecookie", "xpathi"}
    legacy_response = False
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        # Legacy repository prompts use Q1-Q4 rather than the common JSON contract.
        q1 = re.search(r"(?im)^\s*Q1\s*:\s*(TRUE|FALSE)\b", raw)
        q2 = re.search(r"(?im)^\s*Q2\s*:\s*([^\r\n]+)", raw)
        q3 = re.search(r"(?im)^\s*Q3\s*:\s*(\d+|N/?A|NONE)\b", raw)
        q4 = re.search(r"(?im)^\s*Q4\s*:\s*(CWE-?\d+|\d+|N/?A|NONE)\b", raw)
        q5 = re.search(r"(?im)^\s*Q5\s*:\s*(TP|FP)\b", raw)
        if not all((q1, q2, q3, q4)) or (config_id == "baseline-2" and not q5):
            suffix = "Q1-Q5" if config_id == "baseline-2" else "Q1-Q4"
            raise ValueError(f"Response is not valid JSON or a complete legacy {suffix} response")
        assert q1 is not None and q2 is not None and q3 is not None and q4 is not None
        if q2.group(1).strip().lower() not in categories:
            raise ValueError("Legacy Q2 is not one of the categories allowed by the repository prompt")
        vulnerable = q1.group(1).upper() == "TRUE"
        if q5 and (q5.group(1).upper() == "TP") != vulnerable:
            raise ValueError("Legacy Q5 TP/FP conflicts with Q1")
        q4_value = q4.group(1)
        cwe_match = re.fullmatch(r"CWE-?(\d+)", q4_value, flags=re.IGNORECASE)
        cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else ("" if q4_value.upper() in {"N/A", "NA", "NONE"} else q4_value)
        line_value = q3.group(1)
        obj = {"vulnerable": vulnerable, "cwe": cwe, "line": int(line_value) if line_value.isdigit() else None, "reason": ""}
        legacy_response = True
    if isinstance(obj, dict) and "vulnerable" not in obj and "Q1" in obj:
        legacy_response = True
        q1_value = obj["Q1"]
        if isinstance(q1_value, bool):
            vulnerable = q1_value
        elif isinstance(q1_value, str) and q1_value.strip().upper() in {"TRUE", "FALSE"}:
            vulnerable = q1_value.strip().upper() == "TRUE"
        else:
            raise ValueError("Legacy Q1 must be a boolean or TRUE/FALSE string")
        if not all(key in obj for key in ("Q1", "Q2", "Q3", "Q4")):
            raise ValueError("Legacy JSON response must contain Q1, Q2, Q3, and Q4")
        q2 = obj["Q2"]
        if not isinstance(q2, str) or q2.strip().lower() not in categories:
            raise ValueError("Legacy Q2 is not one of the categories allowed by the repository prompt")
        q4 = obj["Q4"]
        if isinstance(q4, int) and not isinstance(q4, bool) and q4 > 0:
            cwe = f"CWE-{q4}"
        elif isinstance(q4, str) and re.fullmatch(r"CWE-?\d+|\d+", q4.strip(), re.IGNORECASE):
            cwe_num = re.search(r"\d+", q4).group(0)
            cwe = f"CWE-{cwe_num}"
        else:
            if isinstance(q4, str) and q4.strip().upper() in {"N/A", "NA", "NONE"}:
                cwe = ""
            else:
                raise ValueError("Legacy Q4 must be a CWE identifier or N/A")
        q3 = obj.get("Q3")
        if isinstance(q3, str) and q3.strip().isdigit():
            q3 = int(q3.strip())
        if isinstance(q3, str) and q3.strip().upper() in {"", "N/A", "NA", "NONE"}:
            q3 = None
        if q3 is not None and (not isinstance(q3, int) or isinstance(q3, bool) or q3 < 1):
            raise ValueError("Legacy Q3 must be a positive line number or N/A")
        q5 = obj.get("Q5")
        if config_id == "baseline-2" and q5 is None:
            raise ValueError("baseline-2 JSON response must include Q5 (TP/FP)")
        if q5 is not None and (not isinstance(q5, str) or q5.strip().upper() not in {"TP", "FP"} or (q5.strip().upper() == "TP") != vulnerable):
            raise ValueError("Legacy Q5 must be TP/FP and agree with Q1")
        obj = {"vulnerable": vulnerable, "cwe": cwe, "line": q3, "reason": ""}
    if config_id in {"baseline-1", "baseline-2"} and not legacy_response:
        raise ValueError(f"{config_id} requires the repository's legacy Q-field response contract")
    if not isinstance(obj, dict) or not isinstance(obj.get("vulnerable"), bool):
        raise ValueError("Response must be a JSON object with boolean 'vulnerable'")
    if not isinstance(obj.get("cwe"), str):
        raise ValueError("Response must include string 'cwe'")
    if obj["cwe"]:
        cwe_match = re.fullmatch(r"CWE-([1-9]\d*)", obj["cwe"], flags=re.IGNORECASE)
        if not cwe_match:
            raise ValueError("'cwe' must be empty or a canonical positive CWE identifier")
        obj["cwe"] = f"CWE-{cwe_match.group(1)}"
    if obj["vulnerable"] and not obj["cwe"]:
        raise ValueError("A vulnerable prediction must include a canonical CWE identifier")
    line = obj.get("line")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
        raise ValueError("'line' must be a positive integer or null")
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
        self.db.execute("CREATE TABLE IF NOT EXISTS tasks (task_id TEXT PRIMARY KEY, status TEXT NOT NULL, detail TEXT, updated_at TEXT NOT NULL, evidence_hash TEXT, verified_at TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS scenarios (scenario_id TEXT PRIMARY KEY, model TEXT NOT NULL, config_id TEXT NOT NULL, status TEXT NOT NULL, detail TEXT, updated_at TEXT NOT NULL, dataset_sha256 TEXT, required_samples INTEGER, experiment_fingerprint TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS sample_runs (scenario_id TEXT NOT NULL, sample_id TEXT NOT NULL, attempt INTEGER NOT NULL, status TEXT NOT NULL, detail TEXT, raw_path TEXT, prediction_path TEXT, updated_at TEXT NOT NULL, raw_sha256 TEXT, prediction_sha256 TEXT, PRIMARY KEY (scenario_id, sample_id, attempt), FOREIGN KEY(scenario_id) REFERENCES scenarios(scenario_id))")
        self.db.execute("CREATE TABLE IF NOT EXISTS scenario_scope (scenario_id TEXT NOT NULL, sample_id TEXT NOT NULL, PRIMARY KEY (scenario_id,sample_id), FOREIGN KEY(scenario_id) REFERENCES scenarios(scenario_id))")
        self.db.execute("CREATE TABLE IF NOT EXISTS evaluations (evaluation_id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL, summary_path TEXT NOT NULL, dataset_sha256 TEXT NOT NULL, status TEXT NOT NULL, evaluated_count INTEGER, coverage REAL, detail TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
        self._ensure_column("tasks", "evidence_hash", "TEXT")
        self._ensure_column("tasks", "verified_at", "TEXT")
        self._ensure_column("scenarios", "dataset_sha256", "TEXT")
        self._ensure_column("scenarios", "required_samples", "INTEGER")
        self._ensure_column("scenarios", "experiment_fingerprint", "TEXT")
        self._ensure_column("sample_runs", "raw_sha256", "TEXT")
        self._ensure_column("sample_runs", "prediction_sha256", "TEXT")
        self.db.execute("UPDATE scenarios SET status='pending',detail='legacy completion had no sample ledger; completion must be revalidated' WHERE status='completed' AND required_samples IS NULL")
        self.db.commit()

    def _ensure_column(self, table: str, column: str, declaration: str) -> None:
        columns = {row[1] for row in self.db.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    def set_task(self, task_id: str, status: str, detail: str = "") -> None:
        if status not in {"pending", "running", "completed", "failed", "blocked"}:
            raise ValueError(f"Invalid task status: {status}")
        self.db.execute("INSERT INTO tasks (task_id,status,detail,updated_at,evidence_hash,verified_at) VALUES (?, ?, ?, ?, NULL, NULL) ON CONFLICT(task_id) DO UPDATE SET status=excluded.status, detail=excluded.detail, updated_at=excluded.updated_at, evidence_hash=NULL, verified_at=NULL", (task_id, status, detail, _now()))
        self.db.commit()

    def set_verified_task(self, task_id: str, detail: str, evidence: str) -> None:
        digest = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
        now = _now()
        self.db.execute("INSERT INTO tasks (task_id,status,detail,updated_at,evidence_hash,verified_at) VALUES (?, 'completed', ?, ?, ?, ?) ON CONFLICT(task_id) DO UPDATE SET status='completed',detail=excluded.detail,updated_at=excluded.updated_at,evidence_hash=excluded.evidence_hash,verified_at=excluded.verified_at", (task_id, detail, now, digest, now))
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
        if status not in {"pending", "running", "completed", "failed", "blocked"}:
            raise ValueError(f"Invalid scenario status: {status}")
        self.db.execute("INSERT INTO scenarios (scenario_id,model,config_id,status,detail,updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(scenario_id) DO UPDATE SET model=excluded.model, config_id=excluded.config_id, status=excluded.status, detail=excluded.detail, updated_at=excluded.updated_at", (scenario_id, model, config_id, status, detail, _now()))
        self.db.commit()

    def register_scenario(self, scenario_id: str, model: str, config_id: str, dataset_sha256: str, required_samples: int, sample_ids: set[str] | None = None, experiment_fingerprint: str | None = None) -> None:
        if required_samples < 1:
            raise ValueError("Scenario must require at least one sample")
        if sample_ids is not None and len(sample_ids) != required_samples:
            raise ValueError("Scenario sample scope must match required_samples exactly")
        row = self.db.execute("SELECT model,config_id,dataset_sha256,required_samples,experiment_fingerprint FROM scenarios WHERE scenario_id=?", (scenario_id,)).fetchone()
        if row:
            if row[2] is None or row[3] is None:
                self.db.execute("UPDATE scenarios SET model=?,config_id=?,dataset_sha256=?,required_samples=?,experiment_fingerprint=?,status='pending',detail='dataset scope registered',updated_at=? WHERE scenario_id=?", (model, config_id, dataset_sha256, required_samples, experiment_fingerprint, _now(), scenario_id))
                self.db.commit()
                row = (model, config_id, dataset_sha256, required_samples, experiment_fingerprint)
            elif row[4] is None and experiment_fingerprint is not None:
                self.db.execute("UPDATE scenarios SET experiment_fingerprint=? WHERE scenario_id=?", (experiment_fingerprint, scenario_id))
                self.db.commit()
                row = (*row[:4], experiment_fingerprint)
            expected = (model, config_id, dataset_sha256, required_samples, experiment_fingerprint)
            actual = (row[0], row[1], row[2], row[3], row[4])
            if actual != expected:
                raise ValueError(f"Scenario ID {scenario_id!r} is already bound to a different model/configuration/dataset/scope/settings fingerprint")
        else:
            self.db.execute("INSERT INTO scenarios (scenario_id,model,config_id,status,detail,updated_at,dataset_sha256,required_samples,experiment_fingerprint) VALUES (?, ?, ?, 'pending', '', ?, ?, ?, ?)", (scenario_id, model, config_id, _now(), dataset_sha256, required_samples, experiment_fingerprint))
            self.db.commit()
        if sample_ids is not None:
            stored = {row[0] for row in self.db.execute("SELECT sample_id FROM scenario_scope WHERE scenario_id=?", (scenario_id,)).fetchall()}
            if stored and stored != sample_ids:
                raise ValueError(f"Scenario ID {scenario_id!r} is already bound to a different sample scope")
            self.db.executemany("INSERT OR IGNORE INTO scenario_scope (scenario_id,sample_id) VALUES (?,?)", [(scenario_id, item) for item in sorted(sample_ids)])
            self.db.commit()

    def record_sample(self, scenario_id: str, sample_id: str, status: str, detail: str = "", raw_path: str | None = None, prediction_path: str | None = None, attempt: int | None = None) -> int:
        if status not in {"pending", "running", "completed", "failed", "blocked", "invalid"}:
            raise ValueError(f"Invalid sample status: {status}")
        if attempt is None:
            attempt = (self.db.execute("SELECT COALESCE(MAX(attempt),0)+1 FROM sample_runs WHERE scenario_id=? AND sample_id=?", (scenario_id, sample_id)).fetchone()[0])
        if not isinstance(attempt, int) or attempt < 1:
            raise ValueError("Could not allocate sample attempt number")
        scope = {row[0] for row in self.db.execute("SELECT sample_id FROM scenario_scope WHERE scenario_id=?", (scenario_id,)).fetchall()}
        if scope and sample_id not in scope:
            raise ValueError(f"Sample {sample_id!r} is outside the registered scenario scope")
        raw_sha = sha256_file(Path(raw_path)) if status == "completed" and raw_path and Path(raw_path).is_file() else None
        prediction_sha = sha256_file(Path(prediction_path)) if status == "completed" and prediction_path and Path(prediction_path).is_file() else None
        if status == "completed" and (not raw_sha or not prediction_sha):
            raise ValueError("A sample cannot be completed without existing raw and normalized prediction artifacts")
        if status == "completed":
            prediction = read_json_strict(Path(prediction_path))
            if not isinstance(prediction, dict) or prediction.get("sample_id") != sample_id:
                raise ValueError("Normalized prediction artifact sample_id does not match the ledger sample")
            parse_prediction(json.dumps(prediction, ensure_ascii=False))
        self.db.execute("INSERT INTO sample_runs (scenario_id,sample_id,attempt,status,detail,raw_path,prediction_path,updated_at,raw_sha256,prediction_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(scenario_id,sample_id,attempt) DO UPDATE SET status=excluded.status,detail=excluded.detail,raw_path=excluded.raw_path,prediction_path=excluded.prediction_path,updated_at=excluded.updated_at,raw_sha256=excluded.raw_sha256,prediction_sha256=excluded.prediction_sha256", (scenario_id, sample_id, attempt, status, detail, raw_path, prediction_path, _now(), raw_sha, prediction_sha))
        self.db.commit()
        self.refresh_scenario(scenario_id)
        return attempt

    def scenario_progress(self, scenario_id: str) -> dict[str, Any]:
        row = self.db.execute("SELECT status,dataset_sha256,required_samples FROM scenarios WHERE scenario_id=?", (scenario_id,)).fetchone()
        if not row:
            raise KeyError(scenario_id)
        records = self.db.execute("SELECT sample_id,attempt,status,detail,raw_path,prediction_path,raw_sha256,prediction_sha256 FROM sample_runs WHERE scenario_id=? ORDER BY sample_id,attempt", (scenario_id,)).fetchall()
        latest: dict[str, tuple[int, str, str]] = {}
        for sample_id, attempt, status, detail, raw_path, prediction_path, raw_sha, prediction_sha in records:
            if status == "completed":
                try:
                    if not raw_path or not prediction_path or sha256_file(Path(raw_path)) != raw_sha or sha256_file(Path(prediction_path)) != prediction_sha:
                        status = "invalid"
                    else:
                        prediction_obj = read_json_strict(Path(prediction_path))
                        if not isinstance(prediction_obj, dict) or prediction_obj.get("sample_id") != sample_id:
                            status = "invalid"
                        else:
                            parse_prediction(json.dumps(prediction_obj, ensure_ascii=False))
                except (OSError, ValueError, TypeError):
                    status = "invalid"
            latest[sample_id] = (attempt, status, detail or "")
        scope = {item[0] for item in self.db.execute("SELECT sample_id FROM scenario_scope WHERE scenario_id=?", (scenario_id,)).fetchall()}
        expected_ids = scope if scope else set(latest)
        completed = sum(sample_id in latest and latest[sample_id][1] == "completed" for sample_id in expected_ids)
        failed_samples = sorted(sample_id for sample_id in expected_ids if sample_id in latest and latest[sample_id][1] in {"failed", "invalid", "blocked"})
        running = any(item[1] == "running" for item in latest.values())
        required = row[2] or 0
        if required and completed >= required:
            status = "completed"
        elif failed_samples:
            status = "failed"
        elif running or completed or latest:
            status = "running"
        else:
            status = "pending"
        pending_ids = sorted(sample_id for sample_id in expected_ids if sample_id not in latest or latest[sample_id][1] != "completed")
        never_attempted = sorted(expected_ids - set(latest))
        return {"scenario_id": scenario_id, "status": status, "dataset_sha256": row[1], "required": required, "completed": completed, "failed": len(failed_samples), "failed_samples": failed_samples, "pending_samples": pending_ids, "never_attempted_samples": never_attempted, "attempts": {sid: val[0] for sid, val in latest.items()}, "sample_statuses": {sid: val[1] for sid, val in latest.items()}, "unprocessed_count": len(pending_ids)}

    def refresh_scenario(self, scenario_id: str) -> dict[str, Any]:
        progress = self.scenario_progress(scenario_id)
        completed = progress["completed"]
        total = progress["required"]
        detail = f"{completed}/{total} required samples completed; {progress['failed']} failed/invalid/blocked"
        model, config_id = self.db.execute("SELECT model,config_id FROM scenarios WHERE scenario_id=?", (scenario_id,)).fetchone()
        self.db.execute("UPDATE scenarios SET status=?,detail=?,updated_at=? WHERE scenario_id=?", (progress["status"], detail, _now(), scenario_id))
        self.db.commit()
        return progress

    def sample_attempts(self, scenario_id: str, sample_id: str) -> list[tuple]:
        return self.db.execute("SELECT attempt,status,detail,raw_path,prediction_path,updated_at,raw_sha256,prediction_sha256 FROM sample_runs WHERE scenario_id=? AND sample_id=? ORDER BY attempt", (scenario_id, sample_id)).fetchall()

    def start_evaluation(self, scenario_id: str, summary_path: str, dataset_sha256: str) -> str:
        evaluation_id = hashlib.sha256(f"{Path(summary_path).resolve()}\0{_now()}".encode()).hexdigest()
        now = _now()
        self.db.execute("INSERT INTO evaluations (evaluation_id,scenario_id,summary_path,dataset_sha256,status,evaluated_count,coverage,detail,created_at,updated_at) VALUES (?, ?, ?, ?, 'running', NULL, NULL, '', ?, ?)", (evaluation_id, scenario_id, str(Path(summary_path).resolve()), dataset_sha256, now, now))
        self.db.commit()
        return evaluation_id

    def finish_evaluation(self, evaluation_id: str, status: str, evaluated_count: int, coverage: float, detail: str = "") -> None:
        if status not in {"completed", "blocked", "failed"}:
            raise ValueError("evaluation status must be completed, blocked, or failed")
        if not 0.0 <= coverage <= 1.0:
            raise ValueError("evaluation coverage must be between 0 and 1")
        cursor = self.db.execute("UPDATE evaluations SET status=?,evaluated_count=?,coverage=?,detail=?,updated_at=? WHERE evaluation_id=?", (status, evaluated_count, coverage, detail, _now(), evaluation_id))
        if cursor.rowcount != 1:
            raise KeyError(evaluation_id)
        self.db.commit()

    def rows(self, table: str) -> list[tuple]:
        if table not in {"tasks", "scenarios", "sample_runs", "evaluations"}:
            raise ValueError("invalid table")
        return self.db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()

    def close(self) -> None:
        self.db.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_label(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def validate_provenance_review(review: Any, subject: str) -> dict[str, str]:
    if not isinstance(review, dict) or not all(isinstance(review.get(key), str) and review[key].strip() for key in ("reviewer", "reviewed_at_utc", "evidence")):
        raise ValueError(f"{subject} manifest requires a non-empty provenance_review with reviewer, reviewed_at_utc, and evidence")
    try:
        timestamp = datetime.fromisoformat(review["reviewed_at_utc"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{subject} provenance review timestamp must be ISO-8601 UTC") from exc
    if timestamp.tzinfo is None:
        raise ValueError(f"{subject} provenance review timestamp must include a timezone")
    return {key: review[key].strip() for key in ("reviewer", "reviewed_at_utc", "evidence")}


def audit_dataset(path: Path, expected_count: int | None = None) -> dict[str, Any]:
    errors: list[str] = []
    error_count = 0
    def add_error(message: str) -> None:
        nonlocal error_count
        error_count += 1
        if len(errors) < 100:
            errors.append(message)
    rows: dict[str, dict[str, Any]] = {}
    label_counts = {"vulnerable": 0, "benign": 0}
    source_hashes: dict[str, str] = {}
    duplicate_source_count = 0
    try:
        with path.open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            required = {"sample_id", "java_source", "target_cwe", "vulnerable"}
            if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
                add_error("CSV header is missing or contains duplicate column names")
            if not reader.fieldnames or not required.issubset(reader.fieldnames):
                add_error(f"CSV header missing required columns: {sorted(required)}")
            else:
                for line_num, row in enumerate(reader, 2):
                    if None in row or any(row.get(column) is None for column in required):
                        add_error(f"row {line_num}: malformed column count or missing required value")
                        continue
                    sample_id = (row.get("sample_id") or "").strip()
                    if not sample_id:
                        add_error(f"row {line_num}: missing sample_id")
                        continue
                    if sample_id in rows:
                        add_error(f"row {line_num}: duplicate sample_id {sample_id}")
                        continue
                    source = (row.get("java_source") or "").strip()
                    if not source:
                        add_error(f"sample {sample_id}: empty Java source")
                    else:
                        source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
                        if source_hash in source_hashes:
                            duplicate_source_count += 1
                            add_error(f"sample {sample_id}: duplicate Java source matches {source_hashes[source_hash]}")
                        source_hashes[source_hash] = sample_id
                    cwe = (row.get("target_cwe") or "").strip()
                    if not re.fullmatch(r"CWE-[1-9]\d*", cwe):
                        add_error(f"sample {sample_id}: invalid target CWE {cwe!r}; expected canonical CWE-<positive integer>")
                    label = _parse_label(row.get("vulnerable") or "")
                    if label is None:
                        add_error(f"sample {sample_id}: ambiguous/invalid ground-truth label {(row.get('vulnerable') or '')!r}")
                    else:
                        label_counts["vulnerable" if label else "benign"] += 1
                    row["sample_id"] = sample_id
                    row["java_source"] = source
                    row["target_cwe"] = cwe
                    row["_label"] = label
                    rows[sample_id] = row
    except (OSError, UnicodeError, csv.Error) as exc:
        add_error(f"dataset unreadable or malformed: {exc}")
    if expected_count is not None and len(rows) != expected_count:
        add_error(f"sample count {len(rows)} does not match required {expected_count}")
    return {"path": str(path), "sample_count": len(rows), "label_counts": label_counts, "duplicate_source_count": duplicate_source_count, "error_count": error_count, "errors": errors, "structurally_valid": error_count == 0, "sha256": sha256_file(path) if path.is_file() else None}


def load_dataset(path: Path) -> dict[str, dict[str, Any]]:
    report = audit_dataset(path)
    if not report["structurally_valid"]:
        raise ValueError("Dataset validation failed: " + "; ".join(report["errors"]))
    rows: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            row["sample_id"] = row["sample_id"].strip()
            row["java_source"] = row["java_source"].strip()
            row["target_cwe"] = row["target_cwe"].strip()
            row["_label"] = _parse_label(row["vulnerable"])
            rows[row["sample_id"]] = row
    return rows


def validate_dataset_manifest(dataset_path: Path, manifest_path: Path, expected_count: int) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    audit = audit_dataset(dataset_path, expected_count)
    if not audit["structurally_valid"]:
        raise ValueError("Dataset validation failed: " + "; ".join(audit["errors"]))
    manifest = read_json_strict(manifest_path)
    required = {"schema_version", "dataset_identity", "version", "source_url", "source_revision", "sample_count", "csv_sha256", "mapping_path", "mapping_sha256", "provenance_review"}
    if not isinstance(manifest, dict) or not required.issubset(manifest):
        raise ValueError(f"Dataset manifest must contain {sorted(required)}")
    if manifest["schema_version"] != 1 or manifest["dataset_identity"] != "OWASP Benchmark Java" or manifest["version"] != "1.2":
        raise ValueError("Dataset manifest must identify OWASP Benchmark Java v1.2 (schema_version 1)")
    parsed_source = urllib.parse.urlparse(manifest["source_url"] if isinstance(manifest["source_url"], str) else "")
    if parsed_source.scheme != "https" or parsed_source.netloc.lower() != "github.com" or parsed_source.path.rstrip("/").lower() not in {"/owasp-benchmark/benchmarkjava", "/owasp-benchmark/benchmarkjava.git"}:
        raise ValueError("Dataset source_url must cite the official OWASP-Benchmark/BenchmarkJava repository")
    if not isinstance(manifest["source_revision"], str) or not re.fullmatch(r"[0-9a-fA-F]{40}", manifest["source_revision"]):
        raise ValueError("Dataset source_revision must be a full 40-character Git commit SHA")
    if manifest["sample_count"] != expected_count or audit["sample_count"] != expected_count:
        raise ValueError(f"Dataset and manifest must each declare {expected_count} samples")
    if manifest["csv_sha256"] != audit["sha256"]:
        raise ValueError("Dataset CSV checksum does not match manifest")
    review = validate_provenance_review(manifest["provenance_review"], "Dataset")
    mapping_path = (manifest_path.parent / str(manifest["mapping_path"])).resolve()
    if not mapping_path.is_file() or not mapping_path.is_relative_to(manifest_path.parent.resolve()):
        raise ValueError("Dataset mapping_path must resolve to a file beside/under the manifest")
    if sha256_file(mapping_path) != manifest["mapping_sha256"]:
        raise ValueError("CWE/ground-truth mapping checksum does not match manifest")
    with mapping_path.open(encoding="utf-8", newline="") as stream:
        mapping_reader = csv.DictReader(stream)
        required_mapping = {"sample_id", "target_cwe", "vulnerable"}
        if not mapping_reader.fieldnames or not required_mapping.issubset(mapping_reader.fieldnames):
            raise ValueError("Normalized mapping CSV must contain sample_id,target_cwe,vulnerable")
        mapping: dict[str, tuple[str, bool]] = {}
        for row in mapping_reader:
            sample_id = row["sample_id"].strip()
            cwe = row["target_cwe"].strip()
            label = _parse_label(row["vulnerable"])
            if not sample_id or sample_id in mapping or not re.fullmatch(r"CWE-[1-9]\d*", cwe) or label is None:
                raise ValueError(f"Invalid or duplicate mapping row for {sample_id!r}")
            mapping[sample_id] = (cwe, label)
    dataset = load_dataset(dataset_path)
    if set(mapping) != set(dataset):
        raise ValueError("Ground-truth mapping IDs do not exactly match dataset IDs")
    conflicts = [sid for sid, row in dataset.items() if (row["target_cwe"], row["_label"]) != mapping[sid]]
    if conflicts:
        raise ValueError(f"Ground-truth/CWE mapping conflicts with dataset rows: {conflicts[:10]}")
    audit["manifest_sha256"] = sha256_file(manifest_path)
    audit["mapping_sha256"] = manifest["mapping_sha256"]
    audit["source_url"] = manifest["source_url"]
    audit["source_revision"] = manifest["source_revision"]
    audit["provenance_review"] = review
    audit["provenance"] = f"CSV/mapping checksums and review attestation validated; source URL/revision are declarations not independently authenticated; reviewer={review['reviewer']} at {review['reviewed_at_utc']} (not cryptographically signed)"
    return audit, dataset


def load_sast(path: Path, expected_dataset_sha256: str | None = None, expected_sample_ids: set[str] | None = None) -> dict[str, dict[str, Any]]:
    manifest = read_json_strict(path)
    required = {"schema_version", "tool", "tool_version", "configuration", "dataset_sha256", "input_path", "input_sha256", "output_path", "output_sha256", "results", "provenance_review"}
    if not isinstance(manifest, dict) or not required.issubset(manifest):
        raise ValueError(f"FindSecBugs manifest must contain {sorted(required)}")
    if manifest["schema_version"] != 1 or manifest["tool"] != "FindSecBugs" or not isinstance(manifest["tool_version"], str) or not manifest["tool_version"].strip():
        raise ValueError("FindSecBugs tool name, version, or manifest schema is invalid")
    if not isinstance(manifest["configuration"], (str, dict)) or not manifest["configuration"]:
        raise ValueError("FindSecBugs analysis configuration is required")
    validate_provenance_review(manifest["provenance_review"], "FindSecBugs")
    if expected_dataset_sha256 and manifest["dataset_sha256"] != expected_dataset_sha256:
        raise ValueError("FindSecBugs manifest refers to a different dataset checksum")
    for key in ("input_path", "output_path"):
        artifact = (path.parent / manifest[key]).resolve()
        if not artifact.is_file() or not artifact.is_relative_to(path.parent.resolve()):
            raise ValueError(f"FindSecBugs {key} must resolve to an artifact under the manifest directory")
        hash_key = "input_sha256" if key == "input_path" else "output_sha256"
        if sha256_file(artifact) != manifest[hash_key]:
            raise ValueError(f"FindSecBugs {key} checksum mismatch")
    results = manifest["results"]
    if not isinstance(results, dict) or not results:
        raise ValueError("FindSecBugs results must be a non-empty sample-keyed object")
    if expected_sample_ids is not None and not set(results).issubset(expected_sample_ids):
        raise ValueError("FindSecBugs results contain IDs outside the verified dataset")
    for sample_id, result in results.items():
        if not isinstance(sample_id, str) or not sample_id or not isinstance(result, dict) or result.get("status") not in {"success", "failed"}:
            raise ValueError(f"Invalid FindSecBugs result status for {sample_id!r}")
        if result["status"] == "failed":
            if not isinstance(result.get("error"), str) or not result["error"].strip():
                raise ValueError(f"Failed FindSecBugs result for {sample_id} must include an error")
            continue
        findings = result.get("findings")
        if not isinstance(findings, list):
            raise ValueError(f"Successful FindSecBugs result for {sample_id} must have a findings list (possibly empty)")
        for finding in findings:
            if not isinstance(finding, dict) or not isinstance(finding.get("rule_id"), str) or not finding["rule_id"].strip() or not isinstance(finding.get("message"), str) or not finding["message"].strip():
                raise ValueError(f"Malformed FindSecBugs finding for {sample_id}")
            if "severity" in finding and not isinstance(finding["severity"], str):
                raise ValueError(f"Invalid FindSecBugs severity for {sample_id}")
            if "source" in finding and not isinstance(finding["source"], str):
                raise ValueError(f"Invalid FindSecBugs source path for {sample_id}")
            if "line" in finding and (not isinstance(finding["line"], int) or isinstance(finding["line"], bool) or finding["line"] < 1):
                raise ValueError(f"Invalid FindSecBugs line number for {sample_id}")
    return results


def ollama_models(endpoint: str = "http://localhost:11434") -> set[str]:
    with urllib.request.urlopen(endpoint.rstrip("/") + "/api/tags", timeout=4) as response:
        return {m["name"] for m in json.load(response).get("models", [])}


def ollama_version(endpoint: str = "http://localhost:11434") -> str:
    with urllib.request.urlopen(endpoint.rstrip("/") + "/api/version", timeout=5) as response:
        body = json.load(response)
    version = body.get("version") if isinstance(body, dict) else None
    if not isinstance(version, str) or not version.strip():
        raise ValueError("Ollama /api/version returned no version string")
    return version


def ollama_model_info(model: str, endpoint: str = "http://localhost:11434") -> dict[str, Any]:
    request = urllib.request.Request(endpoint.rstrip("/") + "/api/show", data=json.dumps({"model": model}).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        body = json.load(response)
    if not isinstance(body, dict):
        raise ValueError(f"Ollama /api/show returned malformed details for {model}")
    return body


def model_supports_thinking(model_info: dict[str, Any]) -> bool:
    if not isinstance(model_info, dict):
        return False
    controls = model_info.get("thinking")
    if controls is True:
        return True
    if isinstance(controls, dict):
        if controls.get("supported") is True:
            return True
        values = controls.get("values", [])
        if isinstance(values, list) and any(value is True or (isinstance(value, str) and value.strip().lower() not in {"", "false", "off", "disabled", "none"}) for value in values):
            return True
    capabilities = model_info.get("capabilities", [])
    return isinstance(capabilities, list) and "thinking" in capabilities


def call_ollama(model: str, prompt: str, generation: dict[str, Any], endpoint: str = "http://localhost:11434", thinking: bool = False, supports_thinking: bool = False) -> tuple[str, bytes]:
    payload = {"model": model, "prompt": prompt, "stream": False, "format": "json", "options": dict(generation)}
    if supports_thinking:
        payload["think"] = bool(thinking)
    request = urllib.request.Request(endpoint.rstrip("/") + "/api/generate", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            raw_envelope = response.read()
        body = json.loads(raw_envelope)
    except Exception as exc:
        raise RuntimeError(f"Ollama /api/generate failed for model {model!r} at {endpoint}: {exc}") from exc
    if not isinstance(body, dict) or body.get("done") is not True or not isinstance(body.get("response"), str):
        raise RuntimeError("Ollama returned an incomplete or malformed generation response")
    return body["response"], raw_envelope


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
    print(f"Scenarios ({scenario_counts}):")
    if not scenarios:
        print("  none recorded")
    for scenario in scenarios:
        progress = state.scenario_progress(scenario[0]) if scenario[7] else None
        if progress:
            print(f"  {scenario[0]}: {progress['status']} {progress['completed']}/{progress['required']} samples; unprocessed={progress['unprocessed_count']}; failed={progress['failed']}")
            if progress["failed_samples"]:
                print(f"    failed/invalid/blocked IDs: {progress['failed_samples'][:20]}")
            if progress["pending_samples"]:
                pending = progress["pending_samples"]
                print(f"    pending IDs: {pending[:20]}" + (f" ... and {len(pending) - 20} more" if len(pending) > 20 else ""))
        else:
            print(f"  {scenario[0]}: {scenario[3]} (dataset scope not registered)")
    sample_rows = state.rows("sample_runs")
    print(f"Sample attempts recorded: {len(sample_rows)}")
    if sample_rows:
        sample_status_counts: dict[str, int] = {}
        for row in sample_rows:
            sample_status_counts[row[3]] = sample_status_counts.get(row[3], 0) + 1
        print(f"  attempt statuses: {sample_status_counts}")
        problem_rows = [row for row in sample_rows if row[3] in {"failed", "invalid", "blocked", "running"}]
        for row in problem_rows[:20]:
            print(f"  {row[0]}/{row[1]} attempt {row[2]}: {row[3]} — {row[4] or ''}")
        if len(problem_rows) > 20:
            print(f"  ... and {len(problem_rows) - 20} more failed/invalid/running attempts")
    evaluations = state.rows("evaluations")
    print(f"Evaluations: {len(evaluations)}")
    for evaluation in evaluations[-20:]:
        print(f"  {evaluation[0][:12]} {evaluation[4]}: {evaluation[5] or 0} evaluated, coverage={evaluation[6] if evaluation[6] is not None else 'n/a'} — {evaluation[7] or ''}; {evaluation[2]}")
    print(f"State database: {db_path}")
    print(f"Raw output root: {DEFAULT_OUTPUT}")


def evaluate_scenario(dataset_path: Path, scenario_dir: Path, summary_path: Path, dataset_manifest_path: Path | None = None) -> dict[str, Any]:
    dataset_audit = None
    if dataset_manifest_path:
        dataset_audit, data = validate_dataset_manifest(dataset_path, dataset_manifest_path, int(read_json_strict(CONFIG_PATH)["dataset"]["required_samples"]))
    else:
        data = load_dataset(dataset_path)
    dataset_sha = sha256_file(dataset_path)
    predictions: dict[str, bool] = {}
    invalid = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(scenario_dir.glob("*.invalid.json"))]
    for path in sorted(scenario_dir.glob("*.prediction.json")):
        obj = json.loads(path.read_text(encoding="utf-8"))
        sample_id = obj.get("sample_id")
        if sample_id not in data or sample_id in predictions:
            invalid.append({"file": str(path), "error": "unknown or duplicate sample_id"})
            continue
        try:
            normalized = parse_prediction(json.dumps(obj))
        except (ValueError, TypeError) as exc:
            invalid.append({"file": str(path), "error": str(exc)})
            continue
        predictions[sample_id] = normalized["vulnerable"]
    failed_calls = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(scenario_dir.glob("*.failed.json"))]
    comparable = sorted(set(data) & set(predictions))
    metrics = calculate_metrics([data[sid]["_label"] for sid in comparable], [predictions[sid] for sid in comparable]) if comparable else None
    raw_artifacts = [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(scenario_dir.glob("*.raw.txt"))]
    metadata_paths = sorted(scenario_dir.glob("*.metadata.json"))
    run_metadata = [json.loads(path.read_text(encoding="utf-8")) for path in metadata_paths]
    mismatched_metadata = [entry.get("sample_id", "unknown") for entry in run_metadata if entry.get("dataset_sha256") not in {None, dataset_sha}]
    if mismatched_metadata:
        raise ValueError(f"Scenario artifacts refer to a different dataset checksum: {mismatched_metadata[:10]}")
    identity_keys = ("scenario_id", "model_tag", "config_id", "experiment_fingerprint")
    identity_values = {key: {entry.get(key) for entry in run_metadata} for key in identity_keys}
    mixed_identity = {key: values for key, values in identity_values.items() if len(values) > 1}
    if mixed_identity:
        raise ValueError(f"Scenario artifacts mix incompatible run identities: {mixed_identity}")
    labels = [row["_label"] for row in data.values()]
    report = {
        "scenario": scenario_dir.name,
        "run_metadata": run_metadata,
        "raw_artifacts": raw_artifacts,
        "dataset": str(dataset_path),
        "dataset_samples": len(data),
        "dataset_sha256": dataset_sha,
        "dataset_provenance": dataset_audit.get("provenance") if dataset_audit else "unverified: no dataset manifest was supplied",
        "ground_truth_counts": {"vulnerable": sum(label is True for label in labels), "benign": sum(label is False for label in labels)},
        "prediction_count": len(predictions),
        "evaluated_count": len(comparable),
        "evaluation_coverage": len(comparable) / len(data) if data else 0.0,
        "metrics_population": "only samples with one valid normalized prediction; missing and invalid predictions are excluded, not treated as benign",
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
    config_data = read_json_strict(CONFIG_PATH)
    dataset_path = Path(args.dataset).resolve()
    if not args.dataset_manifest:
        raise ValueError("--dataset-manifest is required; task status alone is not validation evidence")
    expected_count = int(config_data["dataset"]["required_samples"])
    dataset_audit, data = validate_dataset_manifest(dataset_path, Path(args.dataset_manifest).resolve(), expected_count)
    if args.sample not in data:
        raise ValueError(f"Sample not found: {args.sample}")
    sample, config = data[args.sample], registry[args.config]
    installed_models = ollama_models(args.endpoint)
    if args.model not in installed_models:
        raise ValueError(f"Ollama model tag is not installed: {args.model}")
    model_info = ollama_model_info(args.model, args.endpoint)
    capabilities = model_info.get("capabilities", [])
    supports_thinking = model_supports_thinking(model_info)
    if args.thinking and (args.model != "gemma4:e4b" or not supports_thinking):
        raise ValueError("Thinking mode requires gemma4:e4b and Ollama /api/show capability 'thinking'")
    runtime_version = ollama_version(args.endpoint)
    sast_findings: list[dict[str, Any]] = []
    sast_manifest = None
    if config["sast"] == "findsecbugs":
        if not args.findsecbugs:
            raise ValueError("--findsecbugs manifest is required for this configuration")
        sast_manifest = Path(args.findsecbugs).resolve()
        findings = load_sast(sast_manifest, dataset_audit["sha256"], set(data))
        missing_ids = set(data) - set(findings)
        failed_ids = {sid for sid in set(data) & set(findings) if findings[sid]["status"] != "success"}
        if missing_ids or failed_ids:
            raise ValueError(f"FindSecBugs manifest must contain successful results for the entire scenario dataset; missing={sorted(missing_ids)[:10]}, failed={sorted(failed_ids)[:10]}")
        if args.sample not in findings:
            raise ValueError(f"No FindSecBugs result for sample {args.sample}; refusing to borrow or assume empty findings")
        sample_result = findings[args.sample]
        if sample_result["status"] != "success":
            raise ValueError(f"FindSecBugs analysis failed for {args.sample}: {sample_result.get('error', 'unspecified error')}")
        sast_findings = sample_result["findings"]
    sast = json.dumps(sast_findings, ensure_ascii=False, sort_keys=True) if config["sast"] == "findsecbugs" else ""
    prompt = render_prompt(config, sample["java_source"], sample["target_cwe"], sast)
    generation = config_data["generation"]
    config_sha256 = sha256_file(CONFIG_PATH)
    experiment_fingerprint = canonical_sha256({"dataset_sha256": dataset_audit["sha256"], "dataset_manifest_sha256": dataset_audit["manifest_sha256"], "model_tag": args.model, "model_info": model_info, "ollama_version": runtime_version, "config_id": args.config, "config_sha256": config_sha256, "prompt_template_sha256": sha256_file(template_path(config)), "generation": generation, "thinking": bool(args.thinking), "thinking_supported": supports_thinking, "findsecbugs_manifest_sha256": sha256_file(sast_manifest) if sast_manifest else None})
    scenario_id = args.scenario_id or f"{args.model}__{args.config}__{'thinking' if args.thinking else 'standard'}__{dataset_audit['sha256'][:12]}"
    if args.scenario_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", args.scenario_id):
        raise ValueError("--scenario-id may contain only letters, numbers, dot, underscore, and hyphen")
    state.register_scenario(scenario_id, args.model, args.config, dataset_audit["sha256"], len(data), set(data), experiment_fingerprint)
    previous = state.sample_attempts(scenario_id, args.sample)
    completed_attempts = [row for row in previous if row[1] == "completed"]
    if completed_attempts:
        latest_success = completed_attempts[-1]
        if not latest_success[3] or not latest_success[4] or not Path(latest_success[3]).is_file() or not Path(latest_success[4]).is_file():
            raise ValueError("Database records a successful sample but its raw/prediction artifacts are missing; inspect before retry")
        successful_raw, successful_prediction = Path(latest_success[3]), Path(latest_success[4])
        attempt_stem = successful_raw.name.removesuffix(".raw.txt")
        successful_metadata = successful_raw.with_name(attempt_stem + ".metadata.json")
        if not successful_metadata.is_file():
            raise ValueError("Database records a successful sample but its metadata artifact is missing; inspect before retry")
        meta = json.loads(successful_metadata.read_text(encoding="utf-8"))
        prediction_obj = json.loads(successful_prediction.read_text(encoding="utf-8"))
        if meta.get("dataset_sha256") != dataset_audit["sha256"] or meta.get("rendered_prompt_sha256") != hashlib.sha256(prompt.encode()).hexdigest() or meta.get("experiment_fingerprint") != experiment_fingerprint:
            raise ValueError("Prior successful output is bound to a different dataset, prompt, model/runtime, SAST manifest, or generation settings; refusing resume")
        if meta.get("raw_response_sha256") != sha256_file(successful_raw) or meta.get("prediction_sha256") != sha256_file(successful_prediction) or prediction_obj.get("sample_id") != args.sample:
            raise ValueError("Prior successful output failed checksum/sample verification; refusing resume")
        progress = state.refresh_scenario(scenario_id)
        print(f"Sample {args.sample} already completed; preserved output. Scenario: {progress['status']} {progress['completed']}/{progress['required']}")
        return 0
    outdir = Path(args.output_dir) / scenario_id
    sample_key = hashlib.sha256(args.sample.encode()).hexdigest()[:12]
    outdir.mkdir(parents=True, exist_ok=True)
    attempt_numbers = [row[0] for row in previous]
    for artifact in outdir.glob(f"{sample_key}.attempt-*.*"):
        match = re.match(r".*\.attempt-(\d+)\.", artifact.name)
        if match:
            attempt_numbers.append(int(match.group(1)))
    attempt = max(attempt_numbers, default=0) + 1
    stem = f"{sample_key}.attempt-{attempt:04d}"
    raw_path, input_path, pred_path = (outdir / f"{stem}.{suffix}" for suffix in ("raw.txt", "input.txt", "prediction.json"))
    failed_path = outdir / f"{stem}.failed.json"
    invalid_path = outdir / f"{stem}.invalid.json"
    manifest_path = outdir / f"{stem}.metadata.json"
    api_response_path = outdir / f"{stem}.api-response.json"
    outdir.mkdir(parents=True, exist_ok=True)
    write_raw_output(input_path, prompt)
    metadata = {
        "scenario_id": scenario_id, "sample_id": args.sample, "model_tag": args.model,
        "model_details": model_info.get("details", {}), "model_capabilities": capabilities,
        "ollama_runtime_version": runtime_version,
        "config_id": args.config, "prompt_id": config["prompt_id"], "prompt_version": config["version"],
        "source_status": config["source_status"], "sast_condition": config["sast"],
        "thinking": bool(args.thinking), "thinking_supported": supports_thinking,
        "think_parameter": bool(args.thinking) if supports_thinking else None,
        "generation": generation,
        "ollama_request": {"format": "json", "stream": False, "options": generation, **({"think": bool(args.thinking)} if supports_thinking else {})},
        "experiment_config_sha256": config_sha256, "experiment_fingerprint": experiment_fingerprint,
        "dataset_path": str(dataset_path),
        "dataset_identity": "OWASP Benchmark Java v1.2",
        "dataset_samples": len(data),
        "dataset_sha256": dataset_audit["sha256"], "dataset_manifest_sha256": dataset_audit["manifest_sha256"],
        "cwe_ground_truth_mapping_sha256": dataset_audit["mapping_sha256"], "dataset_source_url": dataset_audit["source_url"],
        "dataset_source_revision": dataset_audit["source_revision"], "dataset_provenance_note": dataset_audit["provenance"],
        "rendered_prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "raw_response_path": str(raw_path), "api_response_path": str(api_response_path), "sample_attempt": attempt, "started_at_utc": _now(),
    }
    if sast_manifest:
        sast_metadata = read_json_strict(sast_manifest)
        metadata["findsecbugs"] = {"manifest_path": str(sast_manifest), "manifest_sha256": sha256_file(sast_manifest), "tool_version": sast_metadata["tool_version"], "configuration": sast_metadata["configuration"], "input_sha256": sast_metadata["input_sha256"], "output_sha256": sast_metadata["output_sha256"], "sample_findings_count": len(sast_findings), "sample_result_status": "success", "provenance_review": sast_metadata["provenance_review"], "provenance_limit": "review attestation is not a cryptographic proof of tool execution"}
    with manifest_path.open("x", encoding="utf-8") as stream:
        json.dump(metadata, stream, indent=2)
        stream.write(chr(10))
    state.record_sample(scenario_id, args.sample, "running", detail="model call in progress", attempt=attempt)
    try:
        response_result = call_ollama(args.model, prompt, generation, endpoint=args.endpoint, thinking=args.thinking, supports_thinking=supports_thinking)
        if isinstance(response_result, tuple) and len(response_result) == 2 and isinstance(response_result[0], str) and isinstance(response_result[1], bytes):
            raw, raw_envelope = response_result
            with api_response_path.open("xb") as stream:
                stream.write(raw_envelope)
            metadata["api_response_sha256"] = sha256_file(api_response_path)
        elif isinstance(response_result, str):
            raw = response_result
        else:
            raise RuntimeError("Ollama adapter returned an unsupported response shape")
        write_raw_output(raw_path, raw)
        metadata["raw_response_sha256"] = sha256_file(raw_path)
        if api_response_path.is_file():
            envelope_obj = json.loads(api_response_path.read_bytes())
            metadata["thinking_output_present"] = bool(envelope_obj.get("thinking")) if isinstance(envelope_obj, dict) else False
        try:
            parsed = parse_prediction(raw, args.config)
        except ValueError as exc:
            with invalid_path.open("x", encoding="utf-8") as stream:
                json.dump({"sample_id": args.sample, "error": str(exc), "raw_response_path": str(raw_path)}, stream, indent=2)
                stream.write(chr(10))
            metadata["sample_status"] = "invalid"
            metadata["error"] = str(exc)
            metadata["finished_at_utc"] = _now()
            manifest_path.write_text(json.dumps(metadata, indent=2) + chr(10), encoding="utf-8")
            state.record_sample(scenario_id, args.sample, "invalid", str(exc), str(raw_path), None, attempt)
            raise
        pred_path.write_text(json.dumps({"sample_id": args.sample, **parsed}, indent=2) + chr(10), encoding="utf-8")
        metadata["prediction_sha256"] = sha256_file(pred_path)
        metadata["sample_status"] = "completed"
        metadata["finished_at_utc"] = _now()
        manifest_path.write_text(json.dumps(metadata, indent=2) + chr(10), encoding="utf-8")
        state.record_sample(scenario_id, args.sample, "completed", "", str(raw_path), str(pred_path), attempt)
        progress = state.scenario_progress(scenario_id)
        print(f"Completed selected sample {args.sample}; scenario {progress['status']} ({progress['completed']}/{progress['required']}); raw response: {raw_path}")
        return 0
    except Exception as exc:
        if not invalid_path.exists() and not failed_path.exists():
            with failed_path.open("x", encoding="utf-8") as stream:
                json.dump({"sample_id": args.sample, "error": str(exc), "failed_at_utc": _now()}, stream, indent=2)
                stream.write(chr(10))
        if invalid_path.exists():
            pass
        elif pred_path.is_file() and raw_path.is_file():
            try:
                state.record_sample(scenario_id, args.sample, "completed", "recovered after final artifact write", str(raw_path), str(pred_path), attempt)
            except Exception:
                state.record_sample(scenario_id, args.sample, "failed", str(exc), str(raw_path), None, attempt)
        else:
            metadata["sample_status"] = "failed"
            metadata["error"] = str(exc)
            metadata["finished_at_utc"] = _now()
            manifest_path.write_text(json.dumps(metadata, indent=2) + chr(10), encoding="utf-8")
            state.record_sample(scenario_id, args.sample, "failed", str(exc), str(raw_path) if raw_path.is_file() else None, None, attempt)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Persistent, explicit-selection OWASP SAST–LLM experiment manager")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Show persistent tasks and scenario state")
    validation = sub.add_parser("validate", help="Validate configuration and selected pilot prerequisites; exits nonzero when blocked")
    validation.add_argument("--config", choices=["baseline-1", "baseline-2", "zero-shot-none", "zero-shot-findsecbugs", "cot-none", "cot-findsecbugs", "tot-none", "tot-findsecbugs"])
    validation.add_argument("--model")
    validation.add_argument("--dataset")
    validation.add_argument("--dataset-manifest")
    validation.add_argument("--findsecbugs")
    validation.add_argument("--sample")
    validation.add_argument("--endpoint", default="http://localhost:11434")
    validation.add_argument("--thinking", action="store_true")
    task = sub.add_parser("task", help="Record a setup task")
    task.add_argument("task_id"); task.add_argument("status", choices=["pending", "running", "blocked", "failed"]); task.add_argument("--detail", default="")
    run = sub.add_parser("run", help="Run exactly one selected sample/configuration")
    run.add_argument("--config", required=True); run.add_argument("--model", required=True); run.add_argument("--dataset", required=True); run.add_argument("--dataset-manifest", required=True); run.add_argument("--sample", required=True); run.add_argument("--findsecbugs"); run.add_argument("--scenario-id"); run.add_argument("--output-dir", default=str(DEFAULT_OUTPUT)); run.add_argument("--endpoint", default="http://localhost:11434"); run.add_argument("--thinking", action="store_true")
    summary = sub.add_parser("summary", help="Evaluate one scenario without overwriting prior summaries")
    summary.add_argument("--dataset", required=True); summary.add_argument("--dataset-manifest", required=True); summary.add_argument("--scenario-dir", required=True); summary.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    state = StateStore(args.state)
    try:
        registry = load_registry()
        models = read_json_strict(CONFIG_PATH)["models"]
        state.ensure_setup_tasks()
        state.ensure_scenarios(registry, models)
        if args.command == "status":
            dashboard(state, registry); return 0
        if args.command == "task":
            state.set_task(args.task_id, args.status, args.detail); dashboard(state, registry); return 0
        if args.command == "validate":
            print(f"Configuration: valid ({len(registry)} approved mappings)")
            prompt_files = sorted({template_path(conf).resolve() for conf in registry.values()} | {(ROOT / conf["source_template"]).resolve() for conf in registry.values() if conf.get("source_template")})
            state.set_verified_task("prompts", "Configuration mapping and prompt file fingerprints revalidated", "\n".join(f"{path}:{sha256_file(path)}" for path in prompt_files))
            selected_configs = [args.config] if args.config else list(registry)
            fsb_required = any(registry[cid]["sast"] == "findsecbugs" for cid in selected_configs)
            selected_models = [args.model] if args.model else models
            env_ok = model_ok = True
            tags: set[str] = set()
            model_info_by_tag: dict[str, dict[str, Any]] = {}
            try:
                tags = ollama_models(args.endpoint)
                version = ollama_version(args.endpoint)
                print(f"Environment: Ollama reachable, version={version}; tags={', '.join(sorted(tags))}")
                evidence = [version, json.dumps(sorted(tags))]
                for model in selected_models:
                    if model not in models:
                        print(f"Environment: model {model!r} is not approved")
                        model_ok = False
                        continue
                    if model not in tags:
                        print(f"Environment: missing model tag {model}")
                        model_ok = False
                        continue
                    info = ollama_model_info(model, args.endpoint)
                    model_info_by_tag[model] = info
                    evidence.append(f"{model}:{json.dumps(info, sort_keys=True)}")
                    print(f"Environment: model {model} available; thinking_supported={model_supports_thinking(info)}")
                state.set_verified_task("ollama", "Ollama API version and tags revalidated", version + json.dumps(sorted(tags)))
                if model_ok:
                    state.set_verified_task("models", "Selected approved model tag/details revalidated", "\n".join(evidence))
                else:
                    state.set_task("models", "blocked", "selected model is missing or not approved")
                if model_supports_thinking(model_info_by_tag.get("gemma4:e4b", {})):
                    state.set_verified_task("gemma_thinking", "Ollama /api/show reports an enabled thinking control", json.dumps(model_info_by_tag["gemma4:e4b"], sort_keys=True))
                elif "gemma4:e4b" in selected_models:
                    state.set_task("gemma_thinking", "blocked", "Ollama /api/show did not verify thinking support")
                if args.thinking and args.model != "gemma4:e4b":
                    model_ok = False
                    print("Environment: thinking validation requires --model gemma4:e4b")
                elif args.thinking and not model_supports_thinking(model_info_by_tag.get("gemma4:e4b", {})):
                    model_ok = False
                    print("Environment: requested Gemma thinking mode is not verified")
            except Exception as exc:
                env_ok = False
                model_ok = False
                state.set_task("ollama", "blocked", str(exc))
                state.set_task("models", "blocked", "Ollama environment could not verify approved model tags/details")
                print(f"Environment: FAILED ({exc})")
            dataset_ok = False
            dataset_audit = None
            data = None
            if args.dataset and args.dataset_manifest:
                try:
                    dataset_audit, data = validate_dataset_manifest(Path(args.dataset).resolve(), Path(args.dataset_manifest).resolve(), int(read_json_strict(CONFIG_PATH)["dataset"]["required_samples"]))
                    dataset_ok = True
                    print(f"Dataset: valid structure; n={dataset_audit['sample_count']}; labels={dataset_audit['label_counts']}; duplicate_sources={dataset_audit['duplicate_source_count']}; csv_sha256={dataset_audit['sha256']}; mapping_sha256={dataset_audit['mapping_sha256']}")
                    print(f"Dataset provenance: {dataset_audit['provenance']}")
                    state.set_verified_task("dataset", "Dataset structure, count and checksums revalidated", dataset_audit["sha256"] + dataset_audit["manifest_sha256"])
                    state.set_verified_task("ground_truth", "Target CWE and labels exactly match checksummed mapping", dataset_audit["mapping_sha256"])
                except Exception as exc:
                    state.set_task("dataset", "blocked", str(exc)); state.set_task("ground_truth", "blocked", str(exc))
                    print(f"Prerequisite: dataset/ground truth BLOCKED ({exc})")
            else:
                print("Prerequisite: dataset/ground truth BLOCKED — provide --dataset and --dataset-manifest")
                state.set_task("dataset", "blocked", "dataset CSV and manifest missing")
                state.set_task("ground_truth", "blocked", "dataset mapping missing")
            fsb_ok = not fsb_required
            if fsb_required:
                if not args.findsecbugs or not dataset_audit or not data:
                    print("Prerequisite: FindSecBugs BLOCKED — compatible manifest and verified dataset required")
                    state.set_task("findsecbugs", "blocked", "manifest or dataset missing")
                else:
                    try:
                        fsb = load_sast(Path(args.findsecbugs).resolve(), dataset_audit["sha256"], set(data))
                        scope = {args.sample} if args.sample else set(data)
                        missing = scope - set(fsb)
                        failed = {sid for sid in scope & set(fsb) if fsb[sid]["status"] != "success"}
                        if missing or failed:
                            raise ValueError(f"SAST scope incomplete: missing={sorted(missing)[:10]}, failed={sorted(failed)[:10]}")
                        manifest_obj = json.loads(Path(args.findsecbugs).read_text(encoding="utf-8"))
                        state.set_verified_task("findsecbugs", "FindSecBugs tool/version/config and artifact hashes revalidated", sha256_file(Path(args.findsecbugs)) + manifest_obj["output_sha256"])
                        fsb_ok = True
                        print(f"FindSecBugs: schema/checksums valid; provenance is a human review attestation (not cryptographically authenticated); successful sample results={len(scope)}")
                    except Exception as exc:
                        state.set_task("findsecbugs", "blocked", str(exc)); print(f"Prerequisite: FindSecBugs BLOCKED ({exc})")
            else:
                print("FindSecBugs: not required for selected configuration(s)")
            ready = env_ok and model_ok and dataset_ok and fsb_ok
            print(f"Pilot readiness: {'READY (validation only; no inference sent)' if ready else 'BLOCKED'}")
            if not env_ok or not model_ok:
                return 2
            return 0 if ready else 1
        if args.command == "run":
            return run_one(args, state, registry)
        if args.command == "summary":
            scenario_dir = Path(args.scenario_dir).resolve()
            output_path = Path(args.output).resolve()
            scenario_id = scenario_dir.name
            metadata_files = sorted(scenario_dir.glob("*.metadata.json"))
            if metadata_files:
                first_metadata = read_json_strict(metadata_files[0])
                scenario_id = str(first_metadata.get("scenario_id") or scenario_id)
            evaluation_id = state.start_evaluation(scenario_id, str(output_path), sha256_file(Path(args.dataset)))
            try:
                report = evaluate_scenario(Path(args.dataset), scenario_dir, output_path, Path(args.dataset_manifest))
                prediction_issues = [issue for issue in report["invalid_responses"] if issue.get("error") == "unknown or duplicate sample_id" or str(issue.get("file", "")).endswith(".prediction.json")]
                complete = not report["missing_predictions"] and report["prediction_count"] == report["dataset_samples"] and not prediction_issues
                evaluation_status = "completed" if complete else "blocked"
                detail = f"{report['evaluated_count']}/{report['dataset_samples']} samples evaluated; historical failed/invalid artifacts={len(report['failed_calls']) + len(report['invalid_responses'])}"
                state.finish_evaluation(evaluation_id, evaluation_status, report["evaluated_count"], report["evaluation_coverage"], detail)
            except Exception as exc:
                state.finish_evaluation(evaluation_id, "failed", 0, 0.0, str(exc))
                raise
            print(json.dumps(report, indent=2))
            print(f"Evaluation {evaluation_status}: coverage={report['evaluation_coverage']:.4f}; summary={output_path}")
            return 0 if evaluation_status == "completed" else 1
        return 2
    except Exception as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    finally:
        state.close()


if __name__ == "__main__":
    raise SystemExit(main())
