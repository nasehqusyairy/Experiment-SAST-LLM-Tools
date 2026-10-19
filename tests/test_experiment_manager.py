import csv
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
            path = Path(tmp) / "findings.json"
            path.write_text(json.dumps({"A": ["A finding"], "B": ["B finding"]}), encoding="utf-8")
            findings = em.load_sast(path)
            prompt = em.render_prompt(em.load_registry()["zero-shot-findsecbugs"], "class A {}", "CWE-89", findings["A"])
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
        legacy = em.parse_prediction("Q1: TRUE\nQ3: 4\nQ4: CWE-89")
        self.assertEqual(legacy["cwe"], "CWE-89")
        legacy_json = em.parse_prediction('{"Q1":true,"Q2":"sqli","Q3":4,"Q4":89}')
        self.assertEqual((legacy_json["vulnerable"], legacy_json["cwe"], legacy_json["line"]), (True, "CWE-89", 4))
        metrics = em.calculate_metrics([True, False, True, False], [True, True, False, False])
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]), (1, 1, 1, 1))
        self.assertEqual(metrics["f1"], 0.5)
        self.assertEqual(metrics["mcc"], 0.0)


class StateTests(unittest.TestCase):
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
                    writer.writerow([f"S{index}", "class A {}", "CWE-89", "false"])
            state = em.StateStore(root / "state.sqlite3")
            for task_id in ("dataset", "ground_truth", "prompts", "ollama", "models"):
                state.set_task(task_id, "completed", "test fixture")
            args = Namespace(config="zero-shot-none", model="qwen2.5-coder:7b", dataset=str(dataset), sample="S0", findsecbugs=None, scenario_id=None, output_dir=str(root / "runs"), endpoint="http://localhost:11434", thinking=False)
            with patch.object(em, "ollama_models", return_value={args.model}), patch.object(em, "ollama_model_info", return_value={"details": {}, "capabilities": ["completion"]}), patch.object(em, "ollama_version", return_value="test"), patch.object(em, "call_ollama", return_value='{"vulnerable":false,"cwe":"CWE-89","line":null,"reason":""}') as call:
                self.assertEqual(em.run_one(args, state, em.load_registry()), 0)
                raw_files = list((root / "runs").rglob("*.raw.txt"))
                self.assertEqual(len(raw_files), 1)
                original = raw_files[0].read_text(encoding="utf-8")
                self.assertEqual(em.run_one(args, state, em.load_registry()), 0)
                self.assertEqual(raw_files[0].read_text(encoding="utf-8"), original)
                self.assertEqual(call.call_count, 1)
            state.close()

    def test_evaluation_summary_counts_missing_and_is_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset = root / "data.csv"
            dataset.write_text(chr(10).join(["sample_id,java_source,target_cwe,vulnerable", 'A,"class A {}",CWE-89,true', 'B,"class B {}",CWE-79,false', ""]), encoding="utf-8")
            run = root / "run"
            run.mkdir()
            (run / "a.prediction.json").write_text('{"sample_id":"A","vulnerable":true}', encoding="utf-8")
            summary = root / "summary.json"
            report = em.evaluate_scenario(dataset, run, summary)
            self.assertEqual(report["evaluated_count"], 1)
            self.assertEqual(report["missing_predictions"], ["B"])
            with self.assertRaises(FileExistsError):
                em.evaluate_scenario(dataset, run, summary)


if __name__ == "__main__":
    unittest.main()
