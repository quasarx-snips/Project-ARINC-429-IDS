# Research Log: May 30, 2026
**Researcher:** Bibhab 

**Topic:** BNR Data Mapping & Protocol Scope Refinement

## 1. Observations on BNR Encoding & Label Mapping
After a deep dive into the [AIM technical manual](https://www.aim-online.com/wp-content/uploads/2019/07/aim-tutorial-oview429-190712-u.pdf) and the [AIT Documentation](https://psirep.com/system/files/arinc_protocol_tutorial_wp_gft639a_16.pdf), I focused on the specific bit-mapping for BNR (Binary Number Representation) words.

**Key Technical Takeaways:**
* **The Sign Bit:** Confirmed that for BNR data, Bit 29 is the dedicated sign bit. According to the AIM manual (Page 13), a "0" indicates Plus/North/East/Above, while a "1" indicates Minus/South/West/Below.
* **The Label Flip:** I verified that the Label (Bits 1-8) is transmitted MSB-first, while the rest of the word is LSB-first. This requires a deterministic bit-reversal in our Python decoder to get the correct octal value.
* **Data Field:** BNR encoding utilizes Bits 11 through 29 for the payload. Bit 28 is the Most Significant Bit (MSB), representing ½ of the maximum scale factor, with each subsequent bit being half the value of the previous one.

**Project Impact:** 
This continuous binary scale is the "sweet spot" for our IDS. Unlike BCD, BNR data follows predictable physical flight dynamics, which makes Shannon Entropy $H(X) = -\sum P(x) \log P(x)$ a highly effective tool for spotting injection anomalies without the "noise" of decimal-nibble transitions.

## 2. Security Analysis: Scope Narrowing for IDS Precision
I performed a "Relevance Audit" on our metadata and decided to officially move to a **BNR-only** research scope to ensure the highest detection accuracy.

**Key Technical Takeaways:**
* **BCD Exclusion:** I realized that BCD (Binary Coded Decimal) uses 4-bit "nibbles" to represent decimal digits. This creates artificial entropy spikes during digit roll-overs that don't correlate with physical flight anomalies.
* **Discrete Removal:** Discrete labels (e.g., 371, 377) are mostly static. Running entropy on them is computationally wasteful; they are better suited for simple signature-based checks rather than statistical analysis.
* **Refined Metadata:** I updated `metadata.json` to include specific resolution, max-range, and `alert_threshold` values for 20+ BNR labels, providing the "physical context" our IDS needs.

**Project Impact:** 
By narrowing the scope, we ensure the IDS is "High Precision." This reduces the risk of "Pilot Fatigue" caused by false alarms—a critical ethical consideration in safety-critical avionics. We are choosing depth over breadth for this 14-day sprint.

## 3. Next Steps
* I will finalize the `docs/` folder by uploading the humanized technical notes.
* I will begin **developing** the Shannon Entropy sliding-window function snippet by snippet starting June 1st.
* I need to define the "Malicious Word" test suite (e.g., rapid altitude jumps) to validate our entropy thresholds against the BNR baseline.

#### *Research assisted by BoodleBox AI for data synthesis and documentation structuring.
