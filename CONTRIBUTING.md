# Contributing to Project ARINC 429 IDS

First off, thank you for contributing to the development of this Intrusion Detection System! This project is a collaborative effort between **Bibhab Saha** (Research Lead) and **Arnab Paul** (Lead Developer).

##  Our Co-Development Methodology: "Snippet-by-Snippet"
To ensure maximum precision in our bit-slicing logic and entropy calculations, we follow an incremental development process:

1.  **Atomic Snippets:** Do not submit large, multi-feature scripts. Submit one logical block at a time (e.g., a single function for Parity validation or a specific BNR scaling factor).
2.  **Protocol First:** Every snippet must be verified against the `AIM_Online_ARINC429.pdf` and `AIT_ARINC429.pdf` specifications before submission.
3.  **Metadata Sync:** Any change to the decoding logic must be reflected in the `src/metadata.json` file to maintain a "Single Source of Truth."

##  Technical Standards
All code contributions must adhere to the following ARINC 429 BNR specifications:
*   **Word Length:** Exactly 32 bits.
*   **Bit Mapping:** 
    *   Bits 1-8: Label (Must handle MSB-first transmission reversal).
    *   Bits 9-10: SDI (Source/Destination Identifier).
    *   Bits 11-29: BNR Data (Bit 29 is the Sign Bit).
    *   Bits 30-31: SSM (Sign/Status Matrix).
    *   Bit 32: Parity (Odd parity by default).
*   **Math:** Shannon Entropy calculations must use $\log_2$ and be performed over a sliding window of at least 50 words.

##  Workflow
1.  **Open an Issue:** Before writing code, ensure there is an Issue describing the feature or bug.
2.  **Branching:** Create a feature branch for your snippet (e.g., `feature/label-030-logic`).
3.  **Pull Requests:** Submit a PR once the snippet passes local validation. 
4.  **Peer Review:** Bibhab and Arnab must both review and approve the logic before it is merged into `main`.

##  Testing Requirements
*   Every new decoder function must include at least one "Malicious Word" test case (e.g., an out-of-range altitude value) to verify the IDS alert trigger.
*   Ensure the `src/decoder.py` remains modular and doesn't break existing BNR mappings.

---
**Note:** This is a safety-critical research project. Accuracy in bit-slicing is more important than speed of development.
