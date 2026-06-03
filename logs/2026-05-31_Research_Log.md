# Research Log: May 31, 2026
**Researcher:** Bibhab

**Topic:** Kanban Architecture & Solo Phase Conclusion

## 1. Observations on Entropy Detection & AI Integration
After finalizing the Shannon Entropy Engine and running it against the 300-frame "Micro-Jitter" dataset, I confirmed the critical detection threshold.

**Key Technical Takeaways:**
* **The 10% Entropy Jump:** Pure altitude data (stable cruise) produces $H(X) \approx 3.11$ (39.1% Normalized). Injected data with stealthy micro-jitter produces $H(X) \approx 4.08$ (49.4% Normalized). This 10% delta is our point of interest
* **Static Threshold Trap:** Hard-coded alerts at 45% entropy will cause false positives during legitimate high-activity flight phases (takeoff/landing). The baseline shifts dynamically.
* **Adaptive ML Solution:** Moving from "If/Else" logic to **Isolation Forest (Unsupervised ML)** allows the IDS to learn what "normal" looks like and only flag statistical *changes*, not absolute values.

**Project Impact:**
This pivot ensures the IDS remains "Stealthy-Attack Aware." By using an adaptive model, we can detect injection attempts that stay within physical ‹‹LI››\Delta‹‹/LI›› limits but still introduce detectable statistical noise.

**Evidence:** [Entropy Baseline Screenshot](https://github.com/quasarx-snips/Project-ARINC-429-IDS/blob/main/logs/imgs/Screenshot%202026-05-31%20201552.png)

## 2. Kanban Architecture & Team Handoff Setup
I finalized the GitHub Project board.

**Key Technical Takeaways:**
* **Three-Column Pipeline:** Done (The Foundation) | To Do (Blue Team) | To Do (Red Team)
* **User Story Format:** Each task includes a "Definition of Done" to ensure quality standards and prevent technical debt.


**Project Impact:**
The board now serves as a "Living Specification." I can see exactly what success looks like for each task without needing clarification calls.

## 3. Next Steps
* **Begin Layer 1 (BPRZ Timing Monitor) and Layer 3 (Multi-Label Delta Tracker).
* **Bibhab's Red Team:** Finalize the "Teleport" and "Parity Poisoning" attack scripts to test defense logic.
* **Co-Development:** Snippet-by-snippet integration starting with the Master IDS Pipeline.

---

#### *Research assisted by BoodleBox AI for documentation structuring and Kanban workflow design.*

