---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

---
name: Bug report
about: Create a report to help us improve the ARINC 429 Decoder/IDS
title: '[BUG] '
labels: bug, protocol-logic
assignees: ''

---

**Describe the bug**
A clear and concise description of what the logic error is (e.g., "Label 014 is decoding as negative when it should be positive").

**Technical Details (Crucial for Debugging)**
*   **Target ARINC Label:** (e.g., 030, 014, 076)
*   **Raw 32-bit Input:** (Paste the binary string here, e.g., `11100000000010011100010001111100`)
*   **Expected Decoded Value:** (e.g., 15,000 ft)
*   **Actual Decoded Value:** (e.g., -500 ft)

**To Reproduce**
Steps to reproduce the behavior:
1. Open `src/decoder.py`
2. Run the test case with the bitstring provided above.
3. Observe the output in the console.

**Expected behavior**
A clear description of what the math/logic should have produced based on the AIM/AIT manuals.

**Environment**
*   **Python Version:** (e.g., 3.10)
*   **OS:** (e.g., Windows 11, Ubuntu)
*   **Metadata Version:** (e.g., the date of your last `metadata.json` update)

**Additional context**
Add any other context about the problem here (e.g., "This only happens when the Sign Bit (Bit 29) is set to 1").
