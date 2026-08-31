"""
Accuracy validation script (Phase 6 of the project plan).

Runs every sample in tests/samples/legit/ and tests/samples/phishing/
through the full analysis pipeline, compares the risk verdict against
the folder-based ground-truth label, and prints precision/recall/accuracy.

Run from the backend/ directory with:
    python -m tests.test_accuracy
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.parsers.header_parser import parse_email_headers
from app.analyzers.auth_analyzer import analyze_authentication
from app.analyzers.risk_scorer import compute_risk_assessment, get_domain

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


def analyze_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    parsed = parse_email_headers(raw)
    parsed.pop("_msg_object", None)

    from_domain = get_domain(parsed["basic_headers"].get("from_address", ""))
    sender_ip = parsed["received_chain"][-1]["ip_address"] if parsed["received_chain"] else None

    auth_results = analyze_authentication(
        parsed["authentication_results_raw"], from_domain, sender_ip
    )

    risk = compute_risk_assessment(
        parsed["basic_headers"], parsed["received_chain"], auth_results
    )
    return risk


def run_suite():
    results = []

    for label, folder in [("legit", "legit"), ("phishing", "phishing")]:
        folder_path = os.path.join(SAMPLES_DIR, folder)
        if not os.path.isdir(folder_path):
            continue
        for filename in sorted(os.listdir(folder_path)):
            if not filename.endswith(".txt"):
                continue
            path = os.path.join(folder_path, filename)
            risk = analyze_file(path)
            predicted_phishing = risk["verdict"] != "Likely Safe"
            actual_phishing = (label == "phishing")
            results.append({
                "file": filename,
                "actual": label,
                "predicted_verdict": risk["verdict"],
                "predicted_phishing": predicted_phishing,
                "actual_phishing": actual_phishing,
                "correct": predicted_phishing == actual_phishing,
                "score": risk["score"],
            })

    print(f"{'FILE':<28} {'ACTUAL':<10} {'PREDICTED':<18} {'SCORE':<6} {'RESULT'}")
    print("-" * 80)
    for r in results:
        mark = "CORRECT" if r["correct"] else "WRONG"
        print(f"{r['file']:<28} {r['actual']:<10} {r['predicted_verdict']:<18} {r['score']:<6} {mark}")

    tp = sum(1 for r in results if r["actual_phishing"] and r["predicted_phishing"])
    fp = sum(1 for r in results if not r["actual_phishing"] and r["predicted_phishing"])
    tn = sum(1 for r in results if not r["actual_phishing"] and not r["predicted_phishing"])
    fn = sum(1 for r in results if r["actual_phishing"] and not r["predicted_phishing"])

    total = len(results)
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) and precision == precision and recall == recall else float("nan"))

    print("\n" + "=" * 40)
    print(f"Total samples: {total}")
    print(f"True Positives (phishing correctly flagged): {tp}")
    print(f"False Positives (legit wrongly flagged):      {fp}")
    print(f"True Negatives (legit correctly cleared):     {tn}")
    print(f"False Negatives (phishing missed):            {fn}")
    print("-" * 40)
    print(f"Accuracy:  {accuracy*100:.1f}%")
    print(f"Precision: {precision*100:.1f}%")
    print(f"Recall:    {recall*100:.1f}%")
    print(f"F1 Score:  {f1*100:.1f}%")
    print("=" * 40)


if __name__ == "__main__":
    run_suite()