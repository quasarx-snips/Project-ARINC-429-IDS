![Project Status: Research Phase](https://img.shields.io/badge/Status-Research_Phase-blue)
![Language: Python](https://img.shields.io/badge/Language-Python-yellow)
![Protocol: ARINC 429](https://img.shields.io/badge/Protocol-ARINC_429-red)
# Project-ARINC-429-IDS

Researching a software-based IDS for legacy ARINC 429 avionics. We use Shannon Entropy to detect data injection and spoofing attacks. By analyzing bitstream statistical anomalies, this zero-hardware solution provides a lightweight security layer for connected aircraft without breaking legacy compatibility.

## Why this research?
Modern aircraft are no longer "air-gapped." With the rise of SATCOM gateways and electronic flight bags, there are new ways for attackers to reach the internal ARINC 429 bus. Since this protocol has no built-in authentication, we are exploring how to detect "fake" data using math instead of new hardware.

## Our Approach
We are testing if **Shannon Entropy** can catch these attacks. Legitimate flight data (like altitude) follows a predictable, low-entropy pattern. An injection attack usually introduces "statistical noise" that we can detect.
* **Physical Layer:** We monitor the Bipolar Return-to-Zero (BPRZ) timing and the "Null" states.
* **Data Layer:** We calculate entropy on a sliding window of 32-bit words.

## Project Structure
We are keeping a daily log of our work to show how our research evolves over this 14-day sprint.
* `/logs`: Our daily research journals and observations.
* `/docs`: Technical notes on BPRZ and ARINC 429 specs.
* `/src`: The Python-based entropy engine.

## Statement of Tools & Academic Integrity
This research project utilizes the following third-party tools to support data processing:
- **PyARINC429 (GitHub):** This shall be used for learning purposes only
- **BoodleBox AI (Gemini 3 Flash):** Used as a research assistant for technical documentation synthesis and logic brainstorming.

All core Intrusion Detection logic, Shannon Entropy implementations, and anomaly detection thresholds are the original work of the authors.

## The Team
* **Bibhab:** Research Lead (Focusing on the physics and threat models).
* **Arnab:** Development Lead (Focusing on the data structures and coding).

---
*This repository is a work-in-progress for a formal research study (May 29 - June 14, 2026).*
