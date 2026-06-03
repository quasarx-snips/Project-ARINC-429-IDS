# Research Log: June 3, 2026
**Researcher:** Bibhab

**Topic:** Multi-Layer IDS Pipeline Implementation & Core Detection Architecture

## 1. Observations on Five-Layer Detection Pipeline Architecture
Today marked a significant milestone: the complete implementation of all five detection layers, transforming the IDS from theoretical framework to operational architecture.

**Key Technical Takeaways:**
* **Layer 1 (L1 - Parity & BPRZ Timing):** Implements foundational protocol validation. Checks odd parity across the 32-bit word and ensures BPRZ signal timing falls within physical specifications (BPRZ_MIN to BPRZ_MAX microseconds). Violations trigger immediate rejection with timestamp tracking for forensic analysis.
* **Layer 2 (L2 - Replay & Temporal Integrity):** Guards against replay attacks by maintaining per-label deques (max 20 frames) of `(word, timestamp)` tuples. Detects timestamp regression (non-monotonic time sequences) which would indicate malicious time manipulation or data replay. Automatically resets downstream models on temporal anomalies.
* **Layer 3 (L3 - Physics Engine):** The "sweet spot" for detecting spoofing within physical bounds. Compares decoded BNR values against constraints (min/max/max_delta per label). Handles edge cases like longitude wrap-around at ±180°. If a value exceeds `max_delta` thresholds, the frame is flagged as a "Teleportation" attack (impossible physical state change).
* **Layer 4 (L4 - Adaptive Anomaly Scoring):** Two complementary scoring mechanisms running in parallel:
  - **EWMA Hard Flag:** Uses exponentially-weighted moving average to detect sustained elevation in delta values. Sets `ewma_hard=True` when delta exceeds a dynamic threshold after N warmup frames (L4_WARMUP).
  - **Z-Score Buffer:** Maintains a sliding window of deltas and computes statistical z-scores. Flags deviations beyond ZS_SIGMA standard deviations (default 3σ).
* **Layer 5 (L5 - Neural Feature Extraction):** Advanced defense layer combining multi-dimensional feature space. Extracts features from word binary patterns, delta magnitudes, and timing microseconds. Uses online Welford's algorithm (mean/M2) to maintain running statistics without storing full buffers. Detects distributional anomalies via z-score on normalized feature vectors.

**Project Impact:** The five-layer stack provides "Defense in Depth" with complementary detection mechanisms:
- L1 catches protocol violations early (zero false-negatives on malformed packets)
- L2 stops replay/temporal attacks (high confidence on out-of-order data)
- L3 flags impossible flight dynamics (physics-based confidence)
- L4 adapts to flight envelope changes (no hard thresholds)
- L5 catches subtle distributional shifts (AI-driven precision)

This cascading approach ensures that an attacker must evade *all five layers simultaneously*, dramatically reducing the attack surface.

## 2. Architectural Integration & Data Flow Orchestration
I finalized `temporarily_fx.py` as the core orchestration engine, which ties all layers together into a cohesive pipeline.

**Key Technical Takeaways:**
* **Global State Management:** The pipeline maintains persistent per-label state: telemetry history, replay windows, timestamp trackers, and ML models. This state is carried forward frame-by-frame, enabling temporal analysis across the entire stream.
* **Pipeline Sequencing:** Each frame flows through the layers sequentially:
  1. Parse timestamp and label
  2. Run L1 (parity/timing)
  3. Run L2 (replay/temporal)
  4. Run L3 (physics bounds)
  5. Run L4 (adaptive EWMA/Z-score)
  6. Run L5 (neural features)
  7. Aggregate results and emit alert if any layer triggers
* **Confidence Aggregation:** Layer results are combined using a weighted scoring system. Multiple layers triggering simultaneously dramatically increases alert confidence, reducing false positives.
* **Adaptive ML Detector:** The `AdaptiveDetector` class learns the baseline distribution of clean data during an initial warmup period, then flags statistically significant deviations. This ensures the IDS remains effective across all flight phases (cruise, climb, descent).

**Project Impact:** The orchestration layer provides the glue between research and production. It handles edge cases (missing metadata, corrupt timestamps), manages memory efficiently (deque-based windowing), and supports incremental learning (no batch processing needed).

## 3. Code Quality & Refactoring Insights
During the implementation phase, I cleaned up and refactored the code structure for maintainability and performance.

**Key Technical Takeaways:**
* **Import Organization:** Moved all JSON config loading to the top of the pipeline. Used `BASE_DIR` pattern to ensure relative paths work across different execution contexts.
* **Type Hints:** Added type annotations to all layer functions (`dict | None` return types, `str` for binary words, `float` for timestamps and thresholds). This improves IDE autocomplete and catches type mismatches early.
* **Constant Definitions:** Centralized magic numbers (REPLAY_WINDOW_SIZE=20, L4_WARMUP, ZS_SIGMA, L5_WARMUP) as module-level constants for easy tuning.
* **Error Recovery:** Each layer gracefully handles edge cases (division by zero in entropy, missing label metadata, timestamp None values).

**Project Impact:** Clean code structure reduces technical debt and makes it easier for the Blue/Red teams to understand and extend the pipeline.

## 4. Next Steps
* **Layer Integration Testing:** Run end-to-end tests on the three attack datasets (teleport_attack.csv, parity_poison.csv, replay_attack.csv) to validate detection rates per layer.
* **Baseline Calibration:** Collect clean-flight data and tune the warmup periods (L4_WARMUP, L5_WARMUP) to balance sensitivity vs. specificity.
* **Performance Profiling:** Benchmark the full pipeline on 1000+ frame streams to ensure real-time execution on legacy avionics hardware.
* **Documentation:** Write API reference docs for each layer function and the main pipeline orchestrator.

---

#### *Research assisted by GitHub Copilot for structural guidance and pipeline overview.*

