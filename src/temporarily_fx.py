"""
ARINC 429 Multi-Layer Attack Detection Pipeline
================================================
Layer 1  — Odd-parity check (bit-level integrity)
Layer 2a — Monotonic timestamp regression (replay via stale timestamp)
Layer 2b — Sliding-window replay dedup  (replay via forged/same timestamp)
Layer 3  — Value boundary + kinematic continuity / teleportation check
Layer 4  — Adaptive ML  (EWMA adaptive threshold + Isolation Forest)
             • Learns the real delta distribution per label from clean frames
             • Auto-tightens thresholds well below the static constraints.json ceiling
             • Flags statistically unusual frames even when no hard rule fires
             • Self-corrects via operator feedback (FP → relax, FN → tighten)
             • Persists learned state across runs (model_state.pkl)
             • Resets per-label state when L3 detects an attack, preventing
               stale-baseline cascade false-positives after a regime shift
"""

import csv
import json
import logging
import math
import os
from collections import deque

from adaptive_model import AdaptiveDetector

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_json_config(filename):
    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        logging.warning(f"Configuration file missing: {filename}")
        return {}
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"Syntax error inside {filename}: {e}")
            try:
                f.seek(0)
                raw_data = f.read().strip()
                if raw_data.endswith("}"):
                    sanitized = raw_data.rstrip().rstrip("}").rstrip(",").strip() + "}"
                    return json.loads(sanitized)
            except Exception:
                pass
            return {}


CONSTRAINTS = load_json_config("constraints.json")
METADATA    = load_json_config("metadata.json")

# ── global pipeline state ────────────────────────────────────────────────────

# Per-label last valid decoded value (kinematic continuity)
telemetry_history: dict[str, float] = {}

# Per-label sliding window of (raw_word, ts_ms) pairs (replay dedup)
REPLAY_WINDOW_SIZE = 20
replay_history: dict[str, deque] = {}

# Monotonic timestamp tracker
last_timestamp_ms: int | None = None

# Adaptive ML detector — persists learned state between runs
detector = AdaptiveDetector.load_or_create(CONSTRAINTS)


# ── helpers ──────────────────────────────────────────────────────────────────

def parse_timestamp_ms(ts: str) -> int | None:
    try:
        parts = ts.strip().split(":")
        if len(parts) == 3:
            return int(parts[0]) * 60_000 + int(parts[1]) * 1_000 + int(parts[2])
    except (ValueError, AttributeError):
        pass
    return None


def parse_label(word_32bit: str) -> str:
    wire_bits     = word_32bit[-8:]
    reversed_bits = wire_bits[::-1]
    return oct(int(reversed_bits, 2))[2:].zfill(3)


def decode_bnr_value(word_32bit: str, label: str) -> float:
    data_bits   = word_32bit[3:22]
    is_negative = data_bits[0] == "1"
    raw_val     = int(data_bits[1:], 2)
    if is_negative:
        raw_val = -raw_val
    return float(raw_val) * CONSTRAINTS.get(label, {}).get("resolution", 1.0)


def calculate_entropy(bits: str) -> float:
    if not bits:
        return 0.0
    n  = len(bits)
    p0 = bits.count("0") / n
    p1 = bits.count("1") / n
    h  = 0.0
    if p0 > 0: h -= p0 * math.log2(p0)
    if p1 > 0: h -= p1 * math.log2(p1)
    return h * 100.0


# ── detection layers ─────────────────────────────────────────────────────────

def check_parity(word_32bit: str) -> bool:
    """Layer 1 — ARINC 429 odd parity: total 1-count must be ODD."""
    return word_32bit.count("1") % 2 == 1


def check_timestamp(ts_ms: int | None) -> dict | None:
    """Layer 2a — Monotonic timestamp regression check."""
    global last_timestamp_ms
    if ts_ms is None or last_timestamp_ms is None:
        return None
    if ts_ms < last_timestamp_ms:
        regression = last_timestamp_ms - ts_ms
        return {
            "status": "ALERT", "layer": 2,
            "msg": (
                f"Timestamp Regression: frame time {ts_ms}ms is {regression}ms "
                f"behind last seen {last_timestamp_ms}ms — possible replay"
            ),
        }
    return None


def check_replay_window(label: str, raw_word: str, ts_ms: int | None,
                        label_name: str) -> dict | None:
    """
    Layer 2b — Sliding-window duplicate check.
    Keys on (raw_word, ts_ms): same value at a different timestamp is normal;
    the identical frame re-transmitted with the same timestamp is a replay.
    """
    if label not in replay_history:
        replay_history[label] = deque(maxlen=REPLAY_WINDOW_SIZE)
    key = (raw_word, ts_ms)
    if key in replay_history[label]:
        return {
            "status": "ALERT", "layer": 2,
            "msg": (
                f"Replay Detected on {label_name}: "
                f"identical frame (word + timestamp) seen within last "
                f"{REPLAY_WINDOW_SIZE} transmissions"
            ),
        }
    replay_history[label].append(key)
    return None


# ── main frame analyzer ──────────────────────────────────────────────────────

def analyze_frame(raw_word: str, timestamp_str: str) -> dict:
    global last_timestamp_ms
    ts_ms = parse_timestamp_ms(timestamp_str)

    # ── Layer 1: Parity ──────────────────────────────────────────────────────
    if not check_parity(raw_word):
        if ts_ms is not None and (last_timestamp_ms is None or ts_ms > last_timestamp_ms):
            last_timestamp_ms = ts_ms
        return {
            "status": "ALERT", "layer": 1,
            "msg": "Parity Violation: bit-32 odd-parity check FAILED",
            "ml": None,
        }

    # ── Layer 2a: Timestamp regression ───────────────────────────────────────
    ts_alert = check_timestamp(ts_ms)
    if ts_alert:
        # The bus state is now uncertain: we don't know how much real time
        # elapsed during the injected replay window.  Clear all kinematic
        # history so the next legitimate frame doesn't produce a false-large
        # delta against a now-stale last-known value.
        telemetry_history.clear()
        detector.reset_all_labels()
        ts_alert["ml"] = None
        return ts_alert

    if ts_ms is not None:
        last_timestamp_ms = ts_ms

    # ── Layer 2b: Replay dedup ───────────────────────────────────────────────
    label      = parse_label(raw_word)
    rules      = CONSTRAINTS.get(label, {})
    label_name = rules.get("name", f"Label {label}")

    replay_alert = check_replay_window(label, raw_word, ts_ms, label_name)
    if replay_alert:
        replay_alert["ml"] = None
        return replay_alert

    # ── Layer 3: Value boundary ───────────────────────────────────────────────
    value = decode_bnr_value(raw_word, label)
    if "min_val" in rules and "max_val" in rules:
        if not (rules["min_val"] <= value <= rules["max_val"]):
            detector.reset_label(label)   # reset ML baseline on hard L3 violation
            return {
                "status": "ALERT", "layer": 3,
                "msg": (
                    f"Value Out of Bounds [{label_name}]: "
                    f"{value:.2f} not in [{rules['min_val']}, {rules['max_val']}]"
                ),
                "ml": None,
            }

    # ── Layer 3: Kinematic continuity / teleportation ────────────────────────
    delta_abs = 0.0
    if label in telemetry_history and "max_delta" in rules:
        prev      = telemetry_history[label]
        delta_abs = abs(value - prev)
        # Longitude wrap guard (GPS Longitude 111 and IRS Longitude 311)
        if label in ("111", "311") and delta_abs > 180.0:
            delta_abs = 360.0 - delta_abs
        if delta_abs > rules["max_delta"]:
            del telemetry_history[label]   # reset rule-based baseline; prevents cascade FP
            detector.reset_label(label)    # reset ML baseline; prevents stale-baseline cascade FP
            return {
                "status": "ALERT", "layer": 3,
                "msg": (
                    f"Teleportation on {label_name}: "
                    f"Δ {delta_abs:.2f} exceeds max_delta {rules['max_delta']}"
                ),
                "ml": None,
            }

    # ── Layer 4: Adaptive ML ──────────────────────────────────────────────────
    entropy_pct = calculate_entropy(raw_word)
    ml_result   = detector.check(label, delta_abs, entropy_pct)

    if ml_result["alert"]:
        # Do NOT commit suspicious frame to telemetry or the ML model
        return {
            "status": "ALERT", "layer": 4,
            "msg": ml_result["msg"],
            "ml" : ml_result,
        }

    # ── All checks passed: commit state ──────────────────────────────────────
    telemetry_history[label] = value
    detector.update(label, delta_abs, entropy_pct)

    return {
        "status": "PASS", "layer": None,
        "msg": "Normal variation",
        "ml" : ml_result,
    }


# ── pipeline ─────────────────────────────────────────────────────────────────

def run_pipeline(show_ml_scores: bool = True,
                 persist_model: bool = True):
    datasets = [
        "data/teleport_attack.csv",
        "data/parity_poison.csv",
        "data/replay_attack.csv",
        #"data/test_2.csv",
        #"data/real"
    ]
    TS_ALIASES = {"time (MM:SS:mmm)", "time"}

    grand_tp = grand_fp = grand_tn = grand_fn = 0

    for file_path in datasets:
        # Reset rule-based state between files (separate data streams).
        # The ML detector is NOT reset — it keeps learning across datasets.
        telemetry_history.clear()
        replay_history.clear()
        global last_timestamp_ms
        last_timestamp_ms = None

        print(f"\n{'='*70}")
        print(f"Pipeline: {file_path}")
        print(f"{'='*70}")

        if not os.path.exists(file_path):
            print(f"  [SKIP] file not found: {file_path}")
            continue

        tp = fp = tn = fn = 0

        with open(file_path, mode="r", newline="") as stream:
            reader = csv.DictReader(stream)
            ts_col = next((c for c in reader.fieldnames if c in TS_ALIASES), None)

            for row in reader:
                word      = row["arinc_transmission_received"]
                is_attack = row["is_attack"].strip().lower() == "true"
                ts_str    = row.get(ts_col, "") if ts_col else ""
                fnum      = int(row["frame_number"])

                result      = analyze_frame(word, ts_str)
                entropy_pct = calculate_entropy(word)
                detected    = result["status"] == "ALERT"

                if detected and is_attack:
                    outcome = "TP"; tp += 1
                elif detected and not is_attack:
                    outcome = "FP ⚠"; fp += 1
                elif not detected and is_attack:
                    outcome = "FN ❌"; fn += 1
                else:
                    outcome = "TN"; tn += 1

                status_icon = "🚨 ALERT" if detected else "✅ PASS "
                layer_lbl   = f"L{result['layer']}" if result.get("layer") else "--"

                # Build ML annotation for the line
                ml_txt = ""
                if show_ml_scores and result.get("ml"):
                    ml = result["ml"]
                    if result["layer"] == 4:
                        pass  # message already in result["msg"]
                    elif not ml["warmup_done"]:
                        ml_txt = " [warming-up]"
                    else:
                        parts = [f"EWMA={ml['ewma_score']:.0f}"]
                        if ml.get("if_score", 0) > 0:
                            parts.append(f"IF={ml['if_score']:.0f}")
                        parts.append(f"∑={ml['combined']:.0f}")
                        ml_txt = " [" + " ".join(parts) + "]"

                print(
                    f"Frame {fnum:>4} | "
                    f"Attack: {str(is_attack):<5} | "
                    f"Entropy: {entropy_pct:5.1f}% | "
                    f"{status_icon} ({layer_lbl}) | "
                    f"{outcome:<6}{ml_txt} -> {result['msg']}"
                )

        total     = tp + fp + tn + fn
        precision = tp / (tp + fp) if (tp + fp) else float("nan")
        recall    = tp / (tp + fn) if (tp + fn) else float("nan")
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) else float("nan"))
        fpr       = fp / (fp + tn) if (fp + tn) else float("nan")

        print(f"\n  ┌─ Per-Dataset Stats ──────────────────────────────────┐")
        print(f"  │  TP={tp:<4} FP={fp:<4} TN={tn:<4} FN={fn:<4}  Total={total}         │")
        print(f"  │  Precision={precision:.1%}  Recall={recall:.1%}  "
              f"F1={f1:.1%}  FPR={fpr:.1%}  │")
        print(f"  └──────────────────────────────────────────────────────┘")

        grand_tp += tp; grand_fp += fp; grand_tn += tn; grand_fn += fn

    # ── Adaptive ML model summary ─────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("Adaptive ML Model State (per-label learned parameters)")
    print(f"{'='*70}")
    labels_seen = sorted(detector._labels.keys())
    if not labels_seen:
        print("  (no data yet)")
    for lbl in labels_seen:
        s    = detector.label_summary(lbl)
        name = CONSTRAINTS.get(lbl, {}).get("name", f"Label {lbl}")
        tightening = ""
        if s["constraint_ceiling"] and s["adaptive_threshold"]:
            pct = 100.0 * s["adaptive_threshold"] / s["constraint_ceiling"]
            tightening = f"  ({pct:.1f}% of hard constraint)"
        print(f"  Label {lbl} [{name}]")
        print(f"    Clean samples     : {s['n_clean']}")
        print(f"    EWMA Δ mean / std : {s['ewma_delta_mean']:.4f} / {s['ewma_delta_std']:.4f}")
        print(f"    Adaptive ceiling  : {s['adaptive_threshold']:.4f}"
              f"  (hard: {s['constraint_ceiling']}){tightening}")
        print(f"    σ sensitivity     : {s['sensitivity_sigma']:.2f}")
        print(f"    IF trained        : {s['if_trained']}  "
              f"(buffer: {s['if_buffer_size']} frames)")

    # ── Grand totals ─────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("Grand Total (all datasets combined)")
    print(f"{'='*70}")
    g_total = grand_tp + grand_fp + grand_tn + grand_fn
    g_prec  = grand_tp / (grand_tp + grand_fp) if (grand_tp + grand_fp) else float("nan")
    g_rec   = grand_tp / (grand_tp + grand_fn) if (grand_tp + grand_fn) else float("nan")
    g_f1    = (2 * g_prec * g_rec / (g_prec + g_rec)
               if (g_prec + g_rec) else float("nan"))
    g_fpr   = grand_fp / (grand_fp + grand_tn) if (grand_fp + grand_tn) else float("nan")
    print(f"  TP={grand_tp}  FP={grand_fp}  TN={grand_tn}  FN={grand_fn}  Total={g_total}")
    print(f"  Precision={g_prec:.1%}  Recall={g_rec:.1%}  "
          f"F1={g_f1:.1%}  FPR={g_fpr:.1%}")

    

    print()


if __name__ == "__main__":
    run_pipeline()
