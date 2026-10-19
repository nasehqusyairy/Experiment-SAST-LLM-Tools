import csv
import io
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import experiment_manager as em


class PromptTests(unittest.TestCase):
    def test_registry_has_eight_configs_and_loads_files(self):
        registry = em.load_registry()
        self.assertEqual(len(registry), 8)
        for config in registry.values():
            self.assertTrue(em.template_path(config).is_file())
        for source in ("baseline_1.txt", "baseline_2.txt", "zero_shot.txt", "cot.txt", "tot.txt"):
            self.assertTrue((em.ROOT / "prompts" / source).is_file())
        self.assertEqual(len(em.build_scenarios(registry, ["m1", "m2", "m3"])), 24)
        self.assertEqual(len(em.build_scenarios(registry, ["m1", "m2", "m3"], ["m3"])), 32)

    def test_all_eight_configurations_render_their_declared_context(self):
        registry = em.load_registry()
        self.assertEqual(set(registry), {"baseline-1", "baseline-2", "zero-shot-none", "zero-shot-findsecbugs", "cot-none", "cot-findsecbugs", "tot-none", "tot-findsecbugs"})
        for config_id, config in registry.items():
            sast_context = '[{"rule_id":"SAMPLE-RULE","message":"finding for this sample"}]' if config["sast"] == "findsecbugs" else ""
            rendered = em.render_prompt(config, "class Sample {}", "CWE-89", sast_context)
            self.assertNotIn("{JAVA_SOURCE_CODE}", rendered)
            self.assertNotIn("{CWE_NAME}", rendered)
            if config["sast"] == "none":
                self.assertNotIn("SAMPLE-RULE", rendered, config_id)
            else:
                self.assertIn("SAMPLE-RULE", rendered, config_id)

    def test_renderer_rejects_ground_truth_and_substitutes_target_cwe(self):
        config = em.load_registry()["cot-none"]
        rendered = em.render_prompt(config, "class A {}", "CWE-89", "")
        self.assertIn("CWE-89", rendered)
        with self.assertRaises(ValueError):
            em.render_prompt(config, "class A {}", "CWE-89", "", ground_truth=True)
        with self.assertRaises(ValueError):
            em.render_prompt(config, "class A {}", "", "")

    def test_none_context_and_findsecbugs_sample_isolation(self):
        registry = em.load_registry()
        no_sast = em.render_prompt(registry["zero-shot-none"], "class A {}", "CWE-89", "SECRET FINDING")
        self.assertNotIn("SECRET FINDING", no_sast)
        self.assertNotIn("FindSecBugs", no_sast)
        fsb = em.render_prompt(registry["zero-shot-findsecbugs"], "class A {}", "CWE-89", "SAMPLE-A finding")
        self.assertIn("SAMPLE-A finding", fsb)
        self.assertNotIn("SAMPLE-B", fsb)

    def test_paired_munson_context_has_same_cwe(self):
        registry = em.load_registry()
        for strategy in ("zero-shot", "cot", "tot"):
            none = em.render_prompt(registry[f"{strategy}-none"], "public class A {}", "CWE-89", "")
            fsb = em.render_prompt(registry[f"{strategy}-findsecbugs"], "public class A {}", "CWE-89", "Finding from A")
            self.assertIn("CWE-89", none)
            self.assertIn("CWE-89", fsb)
            self.assertIn("public class A {}", none)
            self.assertIn("public class A {}", fsb)

    def test_findsecbugs_results_remain_keyed_by_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.zip"
            raw = root / "results.sarif"
            source.write_text("source", encoding="utf-8")
            raw.write_text("raw", encoding="utf-8")
            results = {"A": {"status": "success", "findings": [{"rule_id": "X", "message": "A finding"}]}, "B": {"status": "success", "findings": [{"rule_id": "Y", "message": "B finding"}]}}
            path = root / "findings.json"
            path.write_text(json.dumps({"schema_version": 1, "tool": "FindSecBugs", "tool_version": "4.8.6", "configuration": "default", "dataset_sha256": "a" * 64, "input_path": source.name, "input_sha256": em.sha256_file(source), "output_path": raw.name, "output_sha256": em.sha256_file(raw), "provenance_review": {"reviewer": "test", "reviewed_at_utc": "2026-01-01T00:00:00Z", "evidence": "test fixture"}, "results": results}), encoding="utf-8")
            findings = em.load_sast(path, "a" * 64, {"A", "B"})
            prompt = em.render_prompt(em.load_registry()["zero-shot-findsecbugs"], "class A {}", "CWE-89", json.dumps(findings["A"]))
            self.assertIn("A finding", prompt)
            self.assertNotIn("B finding", prompt)

    def test_ground_truth_csv_column_never_enters_rendered_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "data.csv"
            dataset.write_text(chr(10).join(["sample_id,java_source,target_cwe,vulnerable", 'X,"class A {}",CWE-89,false', ""]), encoding="utf-8")
            row = em.load_dataset(dataset)["X"]
            rendered = em.render_prompt(em.load_registry()["cot-none"], row["java_source"], row["target_cwe"], "")
            self.assertNotIn("false", rendered.lower())
            self.assertNotIn("_label", rendered)

    def test_parse_and_metrics(self):
        parsed = em.parse_prediction('{"vulnerable":true,"cwe":"CWE-89","line":4,"reason":"sink"}')
        self.assertTrue(parsed["vulnerable"])
        legacy = em.parse_prediction("Q1: TRUE\nQ2: sqli\nQ3: 4\nQ4: CWE-89")
        self.assertEqual(legacy["cwe"], "CWE-89")
        legacy_json = em.parse_prediction('{"Q1":true,"Q2":"sqli","Q3":4,"Q4":89}')
        self.assertEqual((legacy_json["vulnerable"], legacy_json["cwe"], legacy_json["line"]), (True, "CWE-89", 4))
        metrics = em.calculate_metrics([True, False, True, False], [True, True, False, False])
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]), (1, 1, 1, 1))
        self.assertEqual(metrics["f1"], 0.5)
        self.assertEqual(metrics["mcc"], 0.0)

    def test_baseline_parser_enforces_question_contract(self):
        with self.assertRaisesRegex(ValueError, "Q5"):
            em.parse_prediction('{"Q1":true,"Q2":"sqli","Q3":4,"Q4":89}', "baseline-2")
        valid = '{"Q1":true,"Q2":"sqli","Q3":4,"Q4":89,"Q5":"TP"}'
        self.assertEqual(em.parse_prediction(valid, "baseline-2")["cwe"], "CWE-89")
        with self.assertRaisesRegex(ValueError, "agree with Q1"):
            em.parse_prediction('{"Q1":true,"Q2":"sqli","Q3":4,"Q4":89,"Q5":"FP"}', "baseline-2")
        with self.assertRaisesRegex(ValueError, "categories"):
            em.parse_prediction('{"Q1":true,"Q2":"made-up","Q3":4,"Q4":89}', "baseline-1")

    def test_invalid_legacy_response_is_not_normalized_as_a_classification(self):
        with self.assertRaises(ValueError):
            em.parse_prediction('{"Q1":"TRUE"}')


class AuditTests(unittest.TestCase):
    def test_validation_is_blocked_without_evidence_and_manual_completion_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.sqlite3"
            with patch.object(em, "ollama_models", return_value={"deepseek-coder:6.7b", "qwen2.5-coder:7b", "gemma4:e4b"}), patch.object(em, "ollama_version", return_value="test"), patch.object(em, "ollama_model_info", return_value={"capabilities": ["completion"]}):
                self.assertEqual(em.main(["--state", str(state_path), "validate"]), 1)
            with self.assertRaises(SystemExit) as result:
                em.main(["--state", str(state_path), "task", "dataset", "completed"])
            self.assertEqual(result.exception.code, 2)

    def test_dataset_audit_rejects_empty_source_and_reports_label_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "dataset.csv"
            dataset.write_text("sample_id,java_source,target_cwe,vulnerable\nA,,CWE-89,true\nB,public class B {},CWE-79,false\n", encoding="utf-8")
            report = em.audit_dataset(dataset, expected_count=2)
            self.assertEqual(report["label_counts"], {"vulnerable": 1, "benign": 1})
            self.assertIn("empty Java source", " ".join(report["errors"]))
            self.assertFalse(report["structurally_valid"])

    def test_dataset_audit_flags_duplicate_source_ambiguous_label_and_bad_cwe(self):
        with tempfile.TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "dataset.csv"
            dataset.write_text("sample_id,java_source,target_cwe,vulnerable\nA,public class X {},CWE-89,true\nB,public class X {},CWE-89,false\nC,public class C {},CWE-???,maybe\n", encoding="utf-8")
            report = em.audit_dataset(dataset, expected_count=3)
            issues = " ".join(report["errors"])
            self.assertEqual(report["duplicate_source_count"], 1)
            self.assertIn("ambiguous/invalid ground-truth label", issues)
            self.assertIn("invalid target CWE", issues)

    def test_dataset_manifest_hashes_and_ground_truth_mapping_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset, mapping, manifest_path = root / "dataset.csv", root / "mapping.csv", root / "dataset-manifest.json"
            with dataset.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream); writer.writerow(["sample_id", "java_source", "target_cwe", "vulnerable"])
                writer.writerow(["A", "class A { int x = 1; }", "CWE-89", "true"])
                writer.writerow(["B", "class B { int y = 2; }", "CWE-79", "false"])
            with mapping.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream); writer.writerow(["sample_id", "target_cwe", "vulnerable"])
                writer.writerow(["A", "CWE-89", "true"]); writer.writerow(["B", "CWE-79", "false"])
            manifest = {"schema_version": 1, "dataset_identity": "OWASP Benchmark Java", "version": "1.2", "source_url": "https://github.com/OWASP-Benchmark/BenchmarkJava", "source_revision": "a" * 40, "sample_count": 2, "csv_sha256": em.sha256_file(dataset), "mapping_path": mapping.name, "mapping_sha256": em.sha256_file(mapping), "provenance_review": {"reviewer": "test", "reviewed_at_utc": "2026-01-01T00:00:00Z", "evidence": "fixture"}}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            audit, data = em.validate_dataset_manifest(dataset, manifest_path, expected_count=2)
            self.assertEqual(audit["label_counts"], {"vulnerable": 1, "benign": 1})
            self.assertEqual(set(data), {"A", "B"})
            with mapping.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream); writer.writerow(["sample_id", "target_cwe", "vulnerable"])
                writer.writerow(["A", "CWE-89", "true"]); writer.writerow(["B", "CWE-79", "true"])
            manifest["mapping_sha256"] = em.sha256_file(mapping)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "conflicts"):
                em.validate_dataset_manifest(dataset, manifest_path, expected_count=2)

    def test_environment_failure_returns_distinct_nonzero_status(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(em, "ollama_models", side_effect=ConnectionError("offline")):
            status = em.main(["--state", str(Path(tmp) / "state.sqlite3"), "validate", "--config", "zero-shot-none", "--model", "qwen2.5-coder:7b"])
            self.assertEqual(status, 2)

    def test_findsecbugs_manifest_requires_success_status_and_verified_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "findsecbugs.sarif"
            source = root / "input.zip"
            raw.write_text("{}", encoding="utf-8")
            source.write_text("input", encoding="utf-8")
            manifest = root / "findsecbugs.json"
            manifest.write_text(json.dumps({"schema_version": 1, "tool": "FindSecBugs", "tool_version": "4.8.6", "configuration": "default", "dataset_sha256": "0" * 64, "input_path": source.name, "input_sha256": em.sha256_file(source), "output_path": raw.name, "output_sha256": em.sha256_file(raw), "provenance_review": {"reviewer": "test", "reviewed_at_utc": "2026-01-01T00:00:00Z", "evidence": "test fixture"}, "results": {"A": {"status": "success", "findings": []}}}), encoding="utf-8")
            result = em.load_sast(manifest, expected_dataset_sha256="0" * 64, expected_sample_ids={"A"})
            self.assertEqual(result["A"]["findings"], [])
            obj = json.loads(manifest.read_text(encoding="utf-8"))
            obj["results"]["A"]["findings"] = ["not a finding object"]
            manifest.write_text(json.dumps(obj), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "rule_id and message"):
                em.load_sast(manifest, expected_dataset_sha256="0" * 64, expected_sample_ids={"A"})
            obj["results"]["A"].update({"status": "failed", "findings": [], "error": "scanner failed"})
            manifest.write_text(json.dumps(obj), encoding="utf-8")
            result = em.load_sast(manifest, expected_dataset_sha256="0" * 64, expected_sample_ids={"A"})
            self.assertEqual(result["A"]["status"], "failed")

    def test_validate_returns_zero_only_when_selected_pilot_prerequisites_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset, mapping, manifest_path = root / "dataset.csv", root / "mapping.csv", root / "dataset-manifest.json"
            with dataset.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream); writer.writerow(["sample_id", "java_source", "target_cwe", "vulnerable"])
                for index in range(2740):
                    writer.writerow([f"S{index}", f"class Sample{index} {{ int value = {index}; }}", "CWE-89", "false"])
            with mapping.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream); writer.writerow(["sample_id", "target_cwe", "vulnerable"])
                for index in range(2740):
                    writer.writerow([f"S{index}", "CWE-89", "false"])
            manifest_path.write_text(json.dumps({"schema_version": 1, "dataset_identity": "OWASP Benchmark Java", "version": "1.2", "source_url": "https://github.com/OWASP-Benchmark/BenchmarkJava", "source_revision": "b" * 40, "sample_count": 2740, "csv_sha256": em.sha256_file(dataset), "mapping_path": mapping.name, "mapping_sha256": em.sha256_file(mapping), "provenance_review": {"reviewer": "test-fixture-only", "reviewed_at_utc": "2026-01-01T00:00:00Z", "evidence": "synthetic unit-test fixture, not an experiment dataset"}}), encoding="utf-8")
            state_path = root / "state.sqlite3"
            with patch.object(em, "ollama_models", return_value={"qwen2.5-coder:7b"}), patch.object(em, "ollama_version", return_value="test"), patch.object(em, "ollama_model_info", return_value={"capabilities": ["completion"]}):
                status = em.main(["--state", str(state_path), "validate", "--config", "zero-shot-none", "--model", "qwen2.5-coder:7b", "--dataset", str(dataset), "--dataset-manifest", str(manifest_path), "--sample", "S0"])
            self.assertEqual(status, 0)


class OllamaTests(unittest.TestCase):
    def test_thinking_control_is_explicit_and_complete_api_envelope_is_preserved(self):
        envelope = b'{"done":true,"response":"{}","thinking":"private trace"}'
        self.assertTrue(em.model_supports_thinking({"thinking": {"values": ["low", "medium", "high"]}}))
        with patch.object(em.urllib.request, "urlopen", return_value=io.BytesIO(envelope)) as urlopen:
            result = em.call_ollama("gemma4:e4b", "prompt", {"temperature": 0}, thinking=False, supports_thinking=True)
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data)
        self.assertIs(payload["think"], False)
        self.assertEqual(result, ("{}", envelope))


class StateTests(unittest.TestCase):
    def test_scenario_status_tracks_required_samples_not_successful_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = em.StateStore(Path(tmp) / "state.sqlite3")
            state.register_scenario("pilot", "model", "zero-shot-none", "a" * 64, 2, {"A", "B"})
            raw_a, pred_a = Path(tmp) / "A.raw", Path(tmp) / "A.prediction"
            raw_a.write_text("raw A", encoding="utf-8")
            pred_a.write_text('{"sample_id":"A","vulnerable":false,"cwe":"","line":null,"reason":""}', encoding="utf-8")
            state.record_sample("pilot", "A", "completed", raw_path=str(raw_a), prediction_path=str(pred_a))
            progress = state.scenario_progress("pilot")
            self.assertEqual(progress["status"], "running")
            self.assertEqual((progress["completed"], progress["required"]), (1, 2))
            self.assertEqual(progress["pending_samples"], ["B"])
            raw_b, pred_b = Path(tmp) / "B.raw", Path(tmp) / "B.prediction"
            raw_b.write_text("raw B", encoding="utf-8")
            pred_b.write_text('{"sample_id":"B","vulnerable":false,"cwe":"","line":null,"reason":""}', encoding="utf-8")
            state.record_sample("pilot", "B", "completed", raw_path=str(raw_b), prediction_path=str(pred_b))
            self.assertEqual(state.scenario_progress("pilot")["status"], "completed")
            state.close()
            resumed = em.StateStore(Path(tmp) / "state.sqlite3")
            self.assertEqual(resumed.scenario_progress("pilot")["status"], "completed")
            self.assertEqual(resumed.scenario_progress("pilot")["completed"], 2)
            resumed.close()

    def test_failed_sample_stays_visible_and_retry_preserves_prior_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = em.StateStore(Path(tmp) / "state.sqlite3")
            state.register_scenario("pilot", "model", "zero-shot-none", "b" * 64, 2, {"A", "B"})
            first = state.record_sample("pilot", "A", "failed", detail="API timeout")
            raw, prediction = Path(tmp) / "A.attempt2.raw", Path(tmp) / "A.attempt2.prediction"
            raw.write_text("raw A", encoding="utf-8")
            prediction.write_text('{"sample_id":"A","vulnerable":false,"cwe":"","line":null,"reason":""}', encoding="utf-8")
            second = state.record_sample("pilot", "A", "completed", raw_path=str(raw), prediction_path=str(prediction))
            self.assertEqual((first, second), (1, 2))
            state.record_sample("pilot", "B", "failed", detail="invalid response")
            progress = state.scenario_progress("pilot")
            self.assertEqual(progress["status"], "failed")
            self.assertEqual(progress["failed"], 1)
            self.assertIn("B", progress["failed_samples"])
            self.assertEqual(progress["attempts"]["A"], 2)
            state.close()

    def test_scenario_id_is_bound_to_experiment_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = em.StateStore(Path(tmp) / "state.sqlite3")
            state.register_scenario("bound", "model", "zero-shot-none", "d" * 64, 1, {"A"}, "fingerprint-1")
            with self.assertRaisesRegex(ValueError, "settings fingerprint"):
                state.register_scenario("bound", "model", "zero-shot-none", "d" * 64, 1, {"A"}, "fingerprint-2")
            state.close()

    def test_evaluation_status_is_distinct_from_sample_and_scenario_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = em.StateStore(Path(tmp) / "state.sqlite3")
            state.register_scenario("eval-scenario", "model", "zero-shot-none", "d" * 64, 2, {"A", "B"})
            evaluation_id = state.start_evaluation("eval-scenario", str(Path(tmp) / "summary.json"), "d" * 64)
            state.finish_evaluation(evaluation_id, "blocked", evaluated_count=1, coverage=0.5, detail="one sample missing")
            self.assertEqual(state.rows("evaluations")[0][4], "blocked")
            self.assertEqual(state.scenario_progress("eval-scenario")["status"], "pending")
            db_path = Path(tmp) / "state.sqlite3"
            state.close()
            reopened = em.StateStore(db_path)
            self.assertEqual(reopened.rows("evaluations")[0][4], "blocked")
            self.assertEqual(reopened.scenario_progress("eval-scenario")["status"], "pending")
            reopened.close()

    def test_state_records_tasks_and_preserves_existing_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = em.StateStore(Path(tmp) / "state.sqlite3")
            state.set_task("dataset", "blocked", "not provided")
            self.assertEqual(state.task_status("dataset"), "blocked")
            out = Path(tmp) / "raw.txt"
            out.write_text("first", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                em.write_raw_output(out, "replacement")
            self.assertEqual(out.read_text(encoding="utf-8"), "first")
            state.ensure_setup_tasks()
            self.assertEqual(state.task_status("ground_truth"), "pending")
            state.close()

    def test_selected_sample_run_resumes_without_overwriting_or_calling_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset = root / "full.csv"
            with dataset.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["sample_id", "java_source", "target_cwe", "vulnerable"])
                for index in range(2740):
                    writer.writerow([f"S{index}", f"class A {{ int n = {index}; }}", "CWE-89", "false"])
            mapping = root / "mapping.csv"
            with mapping.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["sample_id", "target_cwe", "vulnerable"])
                for index in range(2740):
                    writer.writerow([f"S{index}", "CWE-89", "false"])
            dataset_manifest = root / "dataset-manifest.json"
            dataset_manifest.write_text(json.dumps({"schema_version": 1, "dataset_identity": "OWASP Benchmark Java", "version": "1.2", "source_url": "https://github.com/OWASP-Benchmark/BenchmarkJava", "source_revision": "a" * 40, "sample_count": 2740, "csv_sha256": em.sha256_file(dataset), "mapping_path": mapping.name, "mapping_sha256": em.sha256_file(mapping), "provenance_review": {"reviewer": "test", "reviewed_at_utc": "2026-01-01T00:00:00Z", "evidence": "test fixture"}}), encoding="utf-8")
            state = em.StateStore(root / "state.sqlite3")
            args = Namespace(config="zero-shot-none", model="qwen2.5-coder:7b", dataset=str(dataset), dataset_manifest=str(dataset_manifest), sample="S0", findsecbugs=None, scenario_id=None, output_dir=str(root / "runs"), endpoint="http://localhost:11434", thinking=False)
            valid_response = '{"vulnerable":false,"cwe":"CWE-89","line":null,"reason":""}'
            with patch.object(em, "ollama_models", return_value={args.model}), patch.object(em, "ollama_model_info", return_value={"details": {}, "capabilities": ["completion"]}), patch.object(em, "ollama_version", return_value="test"), patch.object(em, "call_ollama", side_effect=[RuntimeError("mock timeout"), '{"vulnerable":"not-a-boolean"}', (valid_response, json.dumps({"done": True, "response": valid_response, "thinking": "not a prompt instruction"}).encode()), (valid_response, json.dumps({"done": True, "response": valid_response}).encode())]) as call:
                with self.assertRaisesRegex(RuntimeError, "mock timeout"):
                    em.run_one(args, state, em.load_registry())
                scenario_id = next(row[0] for row in state.rows("scenarios") if row[1] == args.model and row[2] == args.config and row[7] == 2740)
                self.assertEqual(state.scenario_progress(scenario_id)["sample_statuses"]["S0"], "failed")
                with self.assertRaisesRegex(ValueError, "boolean"):
                    em.run_one(args, state, em.load_registry())
                self.assertEqual(state.scenario_progress(scenario_id)["sample_statuses"]["S0"], "invalid")
                self.assertEqual(em.run_one(args, state, em.load_registry()), 0)
                self.assertEqual(state.scenario_progress(scenario_id)["status"], "running")
                raw_files = list((root / "runs").rglob("*.raw.txt"))
                self.assertEqual(len(raw_files), 2)
                successful_raw = next(path for path in raw_files if ".attempt-0003." in path.name)
                original = successful_raw.read_text(encoding="utf-8")
                self.assertEqual(em.run_one(args, state, em.load_registry()), 0)
                self.assertEqual(successful_raw.read_text(encoding="utf-8"), original)
                self.assertEqual(call.call_count, 3)
                self.assertEqual(len(list((root / "runs").rglob("*.failed.json"))), 1)
                self.assertEqual(len(list((root / "runs").rglob("*.invalid.json"))), 1)
                metadata_path = next((root / "runs").rglob("*.attempt-0003.metadata.json"))
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                self.assertEqual(metadata["raw_response_sha256"], em.sha256_file(Path(metadata["raw_response_path"])))
                self.assertEqual(metadata["thinking_output_present"], True)
                self.assertEqual(em.sha256_file(Path(metadata["api_response_path"])), metadata["api_response_sha256"])
                self.assertEqual((Path(metadata["api_response_path"])).read_bytes(), json.dumps({"done": True, "response": valid_response, "thinking": "not a prompt instruction"}).encode())
                self.assertEqual(metadata["ollama_request"]["options"], call.call_args_list[-1].args[2])
                self.assertEqual(state.scenario_progress(scenario_id)["unprocessed_count"], 2739)
                args.sample = "S1"
                self.assertEqual(em.run_one(args, state, em.load_registry()), 0)
                self.assertEqual(state.scenario_progress(scenario_id)["completed"], 2)
                self.assertEqual(state.scenario_progress(scenario_id)["status"], "running")
                self.assertEqual(state.scenario_progress(scenario_id)["unprocessed_count"], 2738)
                self.assertEqual(call.call_count, 4)
            state.close()

    def test_summary_ignores_prediction_without_completed_checksum_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset = root / "data.csv"
            dataset.write_text("sample_id,java_source,target_cwe,vulnerable\nA,public class A {},CWE-89,true\n", encoding="utf-8")
            run = root / "run"
            run.mkdir()
            (run / "orphan.prediction.json").write_text('{"sample_id":"A","vulnerable":true,"cwe":"CWE-89","line":1,"reason":""}', encoding="utf-8")
            report = em.evaluate_scenario(dataset, run, root / "summary.json")
            self.assertEqual(report["prediction_count"], 0)
            self.assertEqual(report["missing_predictions"], ["A"])
            self.assertIn("completed/checksum-verified metadata", " ".join(issue["error"] for issue in report["invalid_responses"]))

    def test_evaluation_summary_counts_missing_and_is_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset = root / "data.csv"
            dataset.write_text(chr(10).join(["sample_id,java_source,target_cwe,vulnerable", 'A,"class A {}",CWE-89,true', 'B,"class B {}",CWE-79,false', ""]), encoding="utf-8")
            run = root / "run"
            run.mkdir()
            (run / "a.prediction.json").write_text('{"sample_id":"A","vulnerable":true,"cwe":"CWE-89","line":1,"reason":"evidence"}', encoding="utf-8")
            summary = root / "summary.json"
            report = em.evaluate_scenario(dataset, run, summary)
            self.assertEqual(report["evaluated_count"], 1)
            self.assertEqual(report["missing_predictions"], ["B"])
            self.assertEqual(report["evaluation_coverage"], 0.5)
            self.assertEqual(report["metrics_population"], "only samples with one valid normalized prediction; missing and invalid predictions are excluded, not treated as benign")
            self.assertEqual(report["dataset_provenance"], "unverified: no dataset manifest was supplied")
            with self.assertRaises(FileExistsError):
                em.evaluate_scenario(dataset, run, summary)

    def test_summary_cli_persists_blocked_coverage_as_evaluation_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset = root / "dataset.csv"
            dataset.write_text("fixture bytes", encoding="utf-8")
            scenario_dir = root / "scenario"
            scenario_dir.mkdir()
            report = {"evaluated_count": 1, "dataset_samples": 2, "prediction_count": 1, "evaluation_coverage": 0.5, "missing_predictions": ["B"], "invalid_responses": [], "failed_calls": []}
            state_path = root / "state.sqlite3"
            with patch.object(em, "evaluate_scenario", return_value=report):
                result = em.main(["--state", str(state_path), "summary", "--dataset", str(dataset), "--dataset-manifest", str(root / "manifest.json"), "--scenario-dir", str(scenario_dir), "--output", str(root / "summary.json")])
            self.assertEqual(result, 1)
            state = em.StateStore(state_path)
            evaluation = state.rows("evaluations")[0]
            self.assertEqual(evaluation[4], "blocked")
            self.assertEqual((evaluation[5], evaluation[6]), (1, 0.5))
            state.close()

    def test_tampered_completed_artifact_invalidates_scenario_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = em.StateStore(root / "state.sqlite3")
            state.register_scenario("one-sample", "model", "zero-shot-none", "c" * 64, 1, {"A"})
            raw, prediction = root / "raw.txt", root / "prediction.json"
            raw.write_text("original raw", encoding="utf-8")
            prediction.write_text('{"sample_id":"A","vulnerable":false,"cwe":"","line":null,"reason":""}', encoding="utf-8")
            state.record_sample("one-sample", "A", "completed", raw_path=str(raw), prediction_path=str(prediction))
            self.assertEqual(state.scenario_progress("one-sample")["status"], "completed")
            raw.write_text("tampered", encoding="utf-8")
            progress = state.scenario_progress("one-sample")
            self.assertEqual(progress["status"], "failed")
            self.assertEqual(progress["sample_statuses"]["A"], "invalid")
            state.close()


if __name__ == "__main__":
    unittest.main()
