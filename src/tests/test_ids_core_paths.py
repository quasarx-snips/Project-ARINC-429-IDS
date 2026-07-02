import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ids_core import DATASETS, run_pipeline


class IdsCorePathTests(unittest.TestCase):
    def test_dataset_paths_are_resolved_from_repo_layout(self):
        self.assertTrue(DATASETS, "expected dataset paths to be configured")
        missing = [path for path in DATASETS if not os.path.exists(path)]
        self.assertFalse(missing, f"missing dataset files: {missing}")

    def test_pipeline_runs_and_returns_metrics(self):
        constraints_path = os.path.join(os.path.dirname(__file__), '..', 'constraints.json')
        with open(constraints_path) as handle:
            constraints = json.load(handle)

        results = run_pipeline(constraints, {})

        self.assertIn('__layer_catches__', results)
        self.assertIn('L1A_parity_poison.csv', results)
        self.assertIn('L3_teleport_attack.csv', results)
        self.assertGreater(results['L1A_parity_poison.csv']['total'], 0)

    def test_pipeline_reports_metrics_for_each_dataset(self):
        constraints_path = os.path.join(os.path.dirname(__file__), '..', 'constraints.json')
        with open(constraints_path) as handle:
            constraints = json.load(handle)

        results = run_pipeline(constraints, {})
        dataset_results = {k: v for k, v in results.items() if not k.startswith('__')}

        for name, result in dataset_results.items():
            self.assertIn('tp', result)
            self.assertIn('fp', result)
            self.assertIn('tn', result)
            self.assertIn('fn', result)
            self.assertGreater(result['total'], 0, f"{name} should have rows to evaluate")


if __name__ == '__main__':
    unittest.main()
