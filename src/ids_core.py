# =============================================================================
# ids_core.py  —  ARINC 429 Intrusion Detection System
# Run: python3 ids_core.py
# =============================================================================

import csv
import json
import math
import os
import warnings
from collections import deque
import numpy as np

warnings.filterwarnings("ignore")

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONSTRAINTS_PATH = os.path.join(BASE_DIR, "constraints.json")

DATASETS = [
    "L1A_parity_poison.csv",
    "L1B_timing_attack.csv",
    "L2A_replay_attack.csv",
    "L2B_replay_dedup.csv",
    "L3_teleport_attack.csv",
    "L3_value_bounds.csv",
    "L4L5_statistical_anomaly.csv"    
]

BPRZ_MIN, BPRZ_MAX = 4.75, 5.25
REPLAY_WINDOW = 20
EWMA_ALPHA = 0.08
L4_WARMUP = 15
L4_SIGMA = 4.0
ZS_WINDOW = 40
ZS_SIGMA = 3.5
L5_WARMUP = 30
L5_SIGMA = 4.0
COMBINED_GATE = 80.0

# ── ARINC / CSV helpers ───────────────────────────────────────────────────────

_TS_ALIASES = {"time (mm:ss:mmm)", "time"}
_WORD_COL = "arinc_transmission_received"
_ATTACK_COL = "is_attack"
_TIMING_COL = "timing_interval_us"

def _ts_col(fieldnames: list) -> str | None:
    for c in fieldnames:
        if c.lower() in _TS_ALIASES: return c
    return None

def _parse_ts(ts: str) -> int | None:
    try:
        p = ts.strip().split(":")
        if len(p) == 3: return int(p[0]) * 60_000 + int(p[1]) * 1_000 + int(p[2])
    except: pass
    return None

def _parse_label(word: str) -> str:
    return oct(int(word[-8:][::-1], 2))[2:].zfill(3)

def _decode_value(word: str, label: str, constraints: dict) -> float:
    data = word[3:22]
    raw = int(data[1:], 2) * (-1 if data[0] == "1" else 1)
    return float(raw) * constraints.get(label, {}).get("resolution", 1.0)

# =============================================================================
# Analysis Layers (Stateless)
# =============================================================================

def L1(word, timing_us, ts_ms, ts_state):
    if word.count("1") % 2 == 0: return {"layer": "L1A", "msg": "Parity violation"}
    if not (BPRZ_MIN <= timing_us <= BPRZ_MAX): return {"layer": "L1B", "msg": "BPRZ timing violation"}
    return None

def L2(word, ts_ms, ts_state, label, replay):
    if ts_ms is not None and ts_state[0] is not None and ts_ms < ts_state[0]:
        return {"layer": "L2A", "msg": "Timestamp regression"}
    ts_state[0] = ts_ms
    key = (word, ts_ms)
    if key in replay[label]: return {"layer": "L2B", "msg": "Replay"}
    replay[label].append(key)
    return None

def L3(word, label, rules, constraints, telemetry):
    value = _decode_value(word, label, constraints)
    if "min_val" in rules and not (rules["min_val"] <= value <= rules["max_val"]):
        return ({"layer": "L3", "msg": "Out of bounds"}, 0.0, value)
    
    delta_abs = 0.0
    if label in telemetry and "max_delta" in rules:
        delta_abs = abs(value - telemetry[label])
        if label in ("111", "311") and delta_abs > 180.0: delta_abs = 360.0 - delta_abs
        if delta_abs > rules["max_delta"]: return ({"layer": "L3", "msg": "Teleportation"}, delta_abs, value)
    return None, delta_abs, value

# =============================================================================
# Main Orchestrator
# =============================================================================

def analyse_frame(word, ts_str, timing_us, constraints, telemetry, replay, ts_state) -> dict:
    ts_ms = _parse_ts(ts_str)
    hit = L1(word, timing_us, ts_ms, ts_state)
    if hit: return {"status": "ALERT", **hit}

    label = _parse_label(word)
    if label not in replay: replay[label] = deque(maxlen=REPLAY_WINDOW)
    
    hit = L2(word, ts_ms, ts_state, label, replay)
    if hit: return {"status": "ALERT", **hit}

    rules = constraints.get(label, {})
    hit, delta_abs, value = L3(word, label, rules, constraints, telemetry)
    if hit: return {"status": "ALERT", **hit}

    telemetry[label] = value
    return {"status": "PASS", "layer": None, "msg": "Passed"}

def run_pipeline(constraints: dict) -> dict:
    results = {}
    layer_catches = {"L1A": 0, "L1B": 0, "L2A": 0, "L2B": 0, "L3": 0}
    
    for file_path in DATASETS:
        telemetry, replay, ts_state = {}, {}, [None]
        name = os.path.basename(file_path)
        tp = fp = tn = fn = 0
        
        if not os.path.exists(file_path): continue

        with open(file_path, newline="") as fh:
            reader = csv.DictReader(fh)
            ts_col = _ts_col(reader.fieldnames or [])
            for row in reader:
                res = analyse_frame(row[_WORD_COL], row.get(ts_col, ""), float(row.get(_TIMING_COL, 5.0)), 
                                    constraints, telemetry, replay, ts_state)
                detected = res["status"] == "ALERT"
                is_attack = row[_ATTACK_COL].strip().lower() == "true"
                
                if detected and is_attack:
                    tp += 1
                    lyr = res.get("layer", "L3")
                    layer_catches[lyr] += 1
                elif detected: fp += 1
                elif is_attack: fn += 1
                else: tn += 1
        
        results[name] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}

    results["__layer_catches__"] = layer_catches
    return results

def main():
    constraints = json.load(open(CONSTRAINTS_PATH)) if os.path.exists(CONSTRAINTS_PATH) else {}
    results = run_pipeline(constraints)
    print("Pipeline finished. Statistics processed (Stateless mode).")

if __name__ == "__main__":
    main()
