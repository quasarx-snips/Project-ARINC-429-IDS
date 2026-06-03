![Project Status: Research Phase](https://img.shields.io/badge/Status-Research_Phase-blue)
![Language: Python](https://img.shields.io/badge/Language-Python-yellow)
![Protocol: ARINC 429](https://img.shields.io/badge/Protocol-ARINC_429-red)
![Research Status: WIP](https://img.shields.io/badge/Status-WIP-purple)

# Project-ARINC-429-IDS

Researching a software-based IDS for legacy ARINC 429 avionics. We use a **5-layer defense-in-depth detection pipeline** combining protocol validation, temporal integrity checks, physics constraints, adaptive baseline learning, and multi-feature anomaly detection to catch data injection and spoofing attacks. This zero-hardware solution provides lightweight security for connected aircraft without breaking legacy compatibility.

## Why this research?

Modern aircraft are no longer "air-gapped." With the rise of SATCOM gateways and electronic flight bags, there are new ways for attackers to reach the internal ARINC 429 bus. Since this protocol has **no built-in authentication or encryption**, a compromised gateway becomes a direct injection point for malicious altitude, heading, or airspeed data—potentially fatal to flight safety.

Our approach: **detect** impossible flight states and statistical anomalies rather than trying to prevent gateway compromise.

## Our Approach

We use a **Defense-in-Depth, 5-layer pipeline** that combines:

1. **L1 - Protocol Validation** (Bit-level): Parity checks + BPRZ signal timing verification
2. **L2 - Temporal Integrity** (Frame-level): Timestamp monotonicity + per-label frame deduplication  
3. **L3 - Physics Constraints** (Value-level): Impossible state detection (teleportation via max_delta bounds)
4. **L4 - Adaptive Baseline Learning** (Statistical): EWMA + rolling z-scores detect sustained anomalies
5. **L5 - Multi-feature Anomaly Detection** (Distributional): Online Welford algorithm learns feature covariance, flags outliers

**Key insight:** An attacker must evade **all 5 layers simultaneously**, making this a high-confidence defense. Legitimate flight data passes all layers; injected data trips at least one.

## Detection Pipeline Architecture

```mermaid
graph TD
    A[INPUT: Raw ARINC 429 Word] --> B[L1: PARITY & BPRZ TIMING]
    
    B -- L1A: Parity Fail --> C1["🛑 ALERT: Protocol Violation"]
    B -- L1B: Timing Fail --> C1
    B -- Pass --> D[L2: REPLAY & TEMPORAL]
    
    D -- L2A: Timestamp Regression --> C2["🛑 ALERT: Time Manipulation"]
    D -- L2B: Frame Duplicate --> C2
    D -- Pass --> E[L3: PHYSICS BOUNDS]
    
    E -- Out of Bounds/Teleportation --> C3["🛑 ALERT: Impossible State"]
    E -- Pass --> F[L4: ADAPTIVE SCORING]
    
    F -- EWMA Hard Flag ∨ Z-Score Outlier --> C4["🛑 ALERT: Statistical Anomaly"]
    F -- Pass --> G[L5: WELFORD FEATURES]
    
    G -- Feature Anomaly Detected --> C5["🛑 ALERT: Distributional Shift"]
    G -- Pass --> H["✅ PASS: Data Forwarded"]
    
    style C1 fill:#ff4d4d,stroke:#333,stroke-width:2px,color:#fff
    style C2 fill:#ff4d4d,stroke:#333,stroke-width:2px,color:#fff
    style C3 fill:#ff4d4d,stroke:#333,stroke-width:2px,color:#fff
    style C4 fill:#ff4d4d,stroke:#333,stroke-width:2px,color:#fff
    style C5 fill:#ff4d4d,stroke:#333,stroke-width:2px,color:#fff
    style H fill:#2ecc71,stroke:#333,stroke-width:2px,color:#fff
```

## Detection Pipeline Layers

| Layer | Purpose | Detection Method | Warmup | False-Neg Risk |
|-------|---------|-----------------|--------|---|
| **L1A** | Parity Integrity | Odd parity check (32-bit word) | Immediate | Zero (protocol) |
| **L1B** | BPRZ Timing | Signal timing 4.75–5.25 µs | Immediate | Zero (physical) |
| **L2A** | Temporal Continuity | Timestamp monotonicity (regression check) | Immediate | Low (time-based) |
| **L2B** | Replay Prevention | Per-label frame deduplication (20-frame window) | Immediate | Low (exact match) |
| **L3** | Physics Compliance | Value bounds + kinematic delta checks (`max_delta`) | Immediate | Medium (stealthy moves) |
| **L4** | Adaptive Anomaly | EWMA (50%) + Z-Score rolling buffer (30%) | 15 frames | Medium (learned baseline) |
| **L5** | Feature Anomaly | Welford online learning per-feature z-scores | 30 frames | Low (distributional) |

**Scoring Aggregation:** Combined = 50% L4_EWMA + 30% L4_ZScore + 20% L5_Welford  
**Alert Threshold:** Combined ≥ 80.0 OR EWMA_Hard=True

## Testing & Evaluation

We validate against **3 attack vectors**:

- **Teleport Attack** (`teleport_attack.csv`): Impossible altitude jumps (exceeds `max_delta` constraint) → Caught by **L3**
- **Parity Poison** (`parity_poison.csv`): Corrupted parity bit → Caught by **L1A**
- **Replay Attack** (`replay_attack.csv`): Duplicate frames with old/same timestamps → Caught by **L2A/L2B**

**Metrics Tracked:**
- Per-layer catch rate (attribution: which layer stopped each attack)
- Precision, Recall, F1-Score, Matthews Correlation Coefficient (MCC)
- False positive rate across clean flight data
- Layer breakdown distribution

## Project Structure

```
Project-ARINC-429-IDS/
│
├── 📄 README.md                          # This file — project overview
├── 📄 LICENSE                            # MIT License
├── 📄 CONTRIBUTING.md                    # Contribution guidelines (5-layer aligned)
├── 📄 SECURITY.md                        # Vulnerability reporting & security policy
├── 📄 requirements.txt                   # Python dependencies (numpy)
│
├── 📁 src/                               # Core IDS implementation
│   ├── ids_core.py                       # Main orchestration pipeline (L1-L5)
│   ├── L1.py                             # Layer 1: Parity & BPRZ timing
│   ├── L2.py                             # Layer 2: Replay & temporal integrity
│   ├── L3.py                             # Layer 3: Physics constraints
│   ├── L4.py                             # Layer 4: Adaptive anomaly scoring
│   ├── L5.py                             # Layer 5: Welford feature anomaly
│   ├── decoder.py                        # ARINC 429 BNR decoder
│   ├── entropy_engine.py                 # Shannon entropy calculations
│   ├── temporarily_fx.py                 # Orchestration helpers (DEPRECATED)
│   ├── constraints.json                  # Per-label physics bounds (min/max/max_delta)
│   ├── metadata.json                     # Label definitions & entropy config
│   ├── teleport_attack.py                # Generate teleportation attack vectors
│   ├── parity_poison.py                  # Generate parity corruption attack vectors
│   └── replay_attack.py                  # Generate frame replay attack vectors
│
├── 📁 data/                              # Attack simulation datasets
│   ├── teleport_attack.csv               # 100 frames: altitude jumps (L3 catch)
│   ├── parity_poison.csv                 # 100 frames: parity bit flip (L1A catch)
│   └── replay_attack.csv                 # 100 frames: frame duplication (L2B catch)
│
├── 📁 docs/                              # Technical documentation
│   ├── QUICKSTART.md                     # Installation, usage, troubleshooting
│   ├── API.md                            # Function signatures for all layers (L1-L5)
│   └── LAYER_SPECIFICATIONS.md           # Detailed threat models & detection methods
│
├── 📁 logs/                              # Daily research journals
│   ├── imgs/                             # Screenshots & diagrams
│   │   └── .gitignore                    # (empty — stores entropy baseline plots)
│   ├── 2026-05-29_Research_Log.md        # Day 1: BPRZ & gateway analysis
│   ├── 2026-05-30_Research_Log.md        # Day 2: BNR data mapping
│   ├── 2026-05-31_Research_Log.md        # Day 3: Entropy & Kanban architecture
│   ├── 2026-06-01_Research_Log.md        # Day 4: Attack simulation frameworks
│   ├── 2026-06-02_Research_Log.md        # Day 5: (Core pipeline development)
│   ├── 2026-06-03_Research_Log.md        # Day 6: Five-layer implementation
│   └── .gitignore                        # Ignores daily humanised logs
│
└── 📁 .github/                           # GitHub-specific configuration
    └── workflows/                        # CI/CD automation (planned)
```

### Key Files Explained

**Core IDS Engine:**
- `src/ids_core.py` — **Main entry point**. Runs the full 5-layer pipeline on CSV datasets. `python3 src/ids_core.py` tests all 3 attack vectors.
- `src/constraints.json` — Kinematic bounds per label (min/max altitude, max descent rate, etc.)
- `src/metadata.json` — Label definitions (names, units, entropy thresholds)

**Layer Implementations:**
- `src/L1.py` → Parity & BPRZ timing (protocol validation)
- `src/L2.py` → Replay dedup & timestamp monotonicity
- `src/L3.py` → Value bounds & kinematic continuity
- `src/L4.py` → EWMA + rolling z-score anomaly detection
- `src/L5.py` → Welford feature-space anomaly detection

**Attack Generation:**
- `src/teleport_attack.py` → Generates 100-frame CSV with altitude jumps (tests L3)
- `src/parity_poison.py` → Generates 100-frame CSV with bit flips (tests L1A)
- `src/replay_attack.py` → Generates 100-frame CSV with frame duplicates (tests L2B)

**Documentation:**
- `docs/QUICKSTART.md` — **Start here** for installation & first run
- `docs/API.md` — API reference for all layer functions
- `docs/LAYER_SPECIFICATIONS.md` — Threat models, false-negative risks, tuning constants

**Research Logs:**
- `logs/2026-06-*.md` — Daily journals tracking research progress and decisions

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Full Pipeline
```bash
python3 src/ids_core.py
```

Expected output: Detection results across 3 attack datasets with per-layer attribution.

### 3. Explore the Code
- API reference: `docs/API.md`
- Layer specs: `docs/LAYER_SPECIFICATIONS.md`
- Setup guide: `docs/QUICKSTART.md`

## Project Timeline

- **May 29 (Day 1)**: BPRZ physical layer & gateway pivot analysis
- **May 30 (Day 2)**: BNR data mapping & scope refinement (20+ labels)
- **May 31 (Day 3)**: Entropy detection baseline & Kanban architecture
- **June 1 (Day 4)**: Attack simulation frameworks (teleport, parity, replay)
- **June 2–3 (Days 5–6)**: Five-layer pipeline implementation ✓
- **June 4–10**: Integration testing, baseline calibration, performance profiling
- **June 11–14**: Documentation, red-team validation, final hardening

## Statement of Tools & Academic Integrity

**AI/Tools Used:**
- **GitHub Copilot**: Structural guidance on 5-layer pipeline architecture, orchestration design, and code organization
- **Google Gemini (Flash)**: Research synthesis, technical documentation, data generation for test datasets
- **PyARINC429**: Learning reference only (not directly used in final implementation)

**Original Work:**
All five detection layers (L1–L5), adaptive ML implementations, Welford online learning, feature extraction logic, scoring aggregation weights (50/30/20), anomaly detection thresholds, and attack simulation frameworks are original research by the authors.

## The Research Team

**Bibhab Saha** — Lead Researcher & IDS Architect

---

*This repository is a work-in-progress for a formal research study (May 29 – June 14, 2026).*
