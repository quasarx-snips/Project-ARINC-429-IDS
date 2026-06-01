# Research Log: June 1, 2026
**Researcher:** Bibhab

**Topic:** Phase 2 Kickoff & Core 32-bit Attack Simulation Frameworks

## 1. Implementing the Teleport Attack & The Label Reversal Realization
Today marked the official kickoff of our Phase 2 development sprint. I focused heavily on building out `data/teleport_attack.py` to target Arnab's Layer 3 physics engine, simulating an impossible altitude drop from 30,000 ft to 5,000 ft using Label 203.

**Key Technical Takeaways:**
* During the coding process, I realized a massive quirk regarding how ARINC 429 handles the 8-bit label on the physical wire. While Octal 203 translates to `10000011` in pure binary, the protocol transmits the label LSB (Least Significant Bit) first. 
* To ensure Arnab’s Layer 2 decoder doesn't misidentify the label as Octal 301 and discard the frame immediately, I had to manually bit-reverse the string to its true wire format: `11000001`.
* I also introduced randomized floating-point noise to the nominal cruise data to simulate true physics behavior rather than a static linear climb.
* **Project Impact:** The resulting dataset perfectly mimics physical bus traffic. This allows Arnab to verify that his multi-label delta tracker remains silent during noisy normal conditions but immediately trips when the data jump breaks our `max_delta` threshold of 25.0 ft.

## 2. Parity Poisoning Optimization & Dynamic Target Injection
Next, I tackled `data/parity_poison.py`. The objective was to cleanly break the odd parity rule on Bit 32 to stress-test Arnab's protocol validation layer.

**Key Technical Takeaways:**
* Instead of hardcoding a predictable injection point, I used `random.randint(10, 90)` to select the target frame for corruption dynamically. This forces the defensive pipeline to genuinely parse and evaluate the structural integrity of every single packet.
* While writing this, I did a deep clean of the script architecture. I realized that calculating relative elapsed time directly within the loop rendered the `base_time` variable and the `datetime` import completely redundant. 
* I heavily streamlined the python footprint by inlining the bit conversion operations and using nested ternary statements directly inside the CSV dictionary writer. 
* **Project Impact:** By stripping out the bulk and dropping unused variables, the execution footprint is incredibly lightweight. The resulting file ensures the blue-team decoder can be rigorously tested against moving-target anomalies.

## 3. Replay Attacks & Temporal Data Duplication
The final scripting task for today was `data/replay_attack.py` to establish our third core attack vector. 

**Key Technical Takeaways:**
* The simulation functions by logging an authentic, physics-compliant 10-frame window of data (frames 20 to 29) directly into a discrete memory array.
* Further down the timeline (at frame 70), the script halts the real-time parameter generation and streams the buffered frames back onto the bus, keeping both the original 32-bit word content and the exact historical timestamps completely intact.
* **Project Impact:** This script specifically targets the temporal tracking mechanics of the IDS. It provides Arnab with the exact baseline data needed to build out downstream time-displacement checks, ensuring the system flags identical data sequences appearing at impossible chronological intervals.

## 4. Next Steps
* I will hand off these three completed attack datasets (`teleport_attack.csv`, `parity_poison.csv`, and `replay_attack.csv`) to Arnab so he can begin testing his Layer 1, 2, and 3 validation loops.
* Tomorrow, I will begin researching the mathematical parameters required for the Adaptive Jitter Generator to lay the groundwork for our Layer 4 Isolation Forest training dataset.

#### *Research assisted by Gemini AI for documentation structuring.
