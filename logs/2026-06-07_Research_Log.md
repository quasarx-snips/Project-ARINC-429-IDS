# Research Log: June 7, 2026

**Researcher:** Bibhab

**Topic:** Low-Level Bitstream Parsing, Telemetry Discontinuity, and Multi-Signal Visualization Refactoring

## 1. Data Ingestion & Alignment Fixes

Today was dedicated to identifying and fixing data corruption issues introduced when applying standard numerical parsing pipelines directly to mixed raw avionics bitstreams.

**Key Technical Takeaways:**

* **String Preservation Deficiencies:** Discovered that Pandas automatically cast the 32-bit binary strings (`arinc_transmission_received`) into integers during CSV ingestion. This dropped critical leading zeros, which corrupted the frame boundaries.
* **Type Safety Guardrails:** Implemented explicit string casting via `str(binary_val).zfill(32)` prior to any parsing execution. This fixed a critical `int object is not subscriptable` runtime crash and restored data block alignment.
* **ARINC 429 Bit Slicing:** Corrected the multi-layer extraction module. The 8-bit Label (bits 1–8) is transmitted MSB-first per byte, requiring a reverse slice (`word[-8:][::-1]`), while the 19-bit signed data payload maps strictly to indices `3:22` in 0-indexed string space.

## 2. Multi-Signal Stream Isolation & Scatter Mapping

Overhauled the visualizer layout logic to change how dataset anomalies are audited, moving away from arbitrary sequential line graphs to parameter-isolated streams.

**Key Technical Takeaways:**

* **Label Interleaving Resolution:** ARINC 429 buses naturally interleave multiple telemetry streams (e.g., Altitude, Heading, Airspeed) on the same wire. Plotting them as a single continuous line graph caused meaningless vertical spike artifacts.
* **Dynamic Panel Isolation:** Built a structural mapping function that splits data sequences by unique Label ID into distinct subplots using `plt.subplots()`. This isolates individual parameter trajectories and completely sanitizes the baseline signal.
* **Anomaly Scatter Overlay:** Converted the visualization style from line plots to high-contrast scatter plots (`alpha=0.5`). Normal states are rendered in soft blue, while active injections are layered as prominent red `x` indicators to expose exact attack timestamps.

## 3. Visual Anomaly Analysis & Attack Characteristics

Analyzed the specific visual signatures of the injected data across the new standardized pipeline to define exactly why each scenario registers as an adversary event.

**Key Technical Takeaways:**

* **Teleport Attacks (L3):** Characterized by sudden, extreme data discontinuities where points break away cleanly from the continuous curve. Because physical aircraft mass restricts instantaneous rate-of-change, these rapid spatial jumps break $\Delta \text{Value} / \Delta \text{Time}$ physics thresholds.
* **Value Bounds Attacks (L3):** Identified by a flat, continuous clamping signature where data completely exhausts its normal curve and merges into a static horizontal line. The attacker floods the bus with maximum-scale or minimum-scale payloads to induce a system-wide failsafe shutdown.
* **Latent Signaling (L1/L2):** Confirmed that timing and parity poison anomalies often display visually stable blue trajectories, meaning the payload value itself mimics normal parameters, but the metadata (timing interval variations or broken odd-parity calculations) exposes the attack profile.

## 4. Next Steps

* **Sign-Bit Verification:** Update the `parse_arinc_bits` payload module to handle negative binary sign bit configurations for spatial parameters that pivot around a zero baseline (e.g., pitch rate, vertical speed).
* **Automated Plot Export:** Integrate the plotting architecture directly with the `ids_core.py` engine so execution immediately saves clean telemetry charts into the `plots/` folder upon file ingestion.
* **Signal Smoothing Evaluation:** Test moving average overlays against the scatter data to determine if a low-pass filter line helps or hinders identifying subtle drift attacks.

---

*Research log maintained to ensure reproducibility of detection performance and architectural transparency.*
