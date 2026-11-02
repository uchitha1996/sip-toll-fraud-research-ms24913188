"""Replay archived event exports; no traffic generation or model deserialization."""
from pathlib import Path
import hashlib
import importlib.util
import json


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    root = Path(__file__).resolve().parents[1] / "research/pbx/accelerated-20261012"
    for manifest, key in [("evaluation_freeze.json", "sha256"), ("results_freeze.json", "hashes")]:
        saved = json.loads((root / manifest).read_text())
        for name, expected in saved[key].items():
            assert sha(root / name) == expected, name
    spec = importlib.util.spec_from_file_location("archived_common_evaluator", root / "common_evaluator.py")
    evaluator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evaluator)
    saved = json.loads((root / "final_results.json").read_text())
    policy = json.loads((root / "policy.json").read_text())
    v6 = evaluator.load_v6(root / "frozen/progression_v6_development.py")
    rows = {method: [] for method in saved["methods"]}
    checked_captures, unavailable_captures = 0, 0
    for case in saved["cases"]:
        run = root / "runs/fresh" / case["id"]
        capture = run / "traffic.pcap"
        if capture.is_file():
            assert sha(capture) == case["verification"]["pcap_sha256"], case["id"]
            checked_captures += 1
        else:
            unavailable_captures += 1
        assert sha(run / "v5/candidate_timeline.csv") == case["verification"]["v5_timeline_sha256"]
        computed, _ = evaluator.predictions(evaluator.read_csv(run / "v5/candidate_timeline.csv"),
                                           evaluator.read_csv(run / "sip_packets.csv"), v6, policy)
        assert computed == case["predictions"], case["id"]
        for method, prediction in computed.items():
            rows[method].append({"truth": int(case["intent"] == "SIMULATED_ABUSE"),
                                 "predicted": prediction["predicted"]})
    for method, data in rows.items():
        computed = evaluator.confusion(data)
        assert all(saved["methods"][method][key] == value for key, value in computed.items()), method
    print(json.dumps({"replayed_cases": len(saved["cases"]), "predictions_and_confusion_match": True,
                      "raw_captures_hash_checked": checked_captures,
                      "raw_captures_not_in_repository": unavailable_captures,
                      "basis": "Frozen event exports; raw-capture validation is separate."}, indent=2))


if __name__ == "__main__":
    main()
