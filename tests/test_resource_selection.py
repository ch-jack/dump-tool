import json
import tempfile
import unittest
from pathlib import Path

import auto


class ResourceSelectionFileTests(unittest.TestCase):
    def load_payload(self, payload):
        with tempfile.TemporaryDirectory() as temp_dir:
            selection_path = Path(temp_dir) / "selected-resources.json"
            selection_path.write_text(json.dumps(payload), encoding="utf-8")
            return auto.load_resource_selection_file(selection_path)

    def test_loads_resources_array(self):
        self.assertEqual(
            self.load_payload({"schemaVersion": 1, "resources": ["alpha", "beta"]}),
            ["alpha", "beta"],
        )

    def test_loads_legacy_single_resource_string(self):
        self.assertEqual(
            self.load_payload({"schemaVersion": 1, "resources": "alpha"}),
            ["alpha"],
        )

    def test_rejects_other_scalar_shapes(self):
        with self.assertRaisesRegex(RuntimeError, "resources array"):
            self.load_payload({"schemaVersion": 1, "resources": 1})


if __name__ == "__main__":
    unittest.main()
