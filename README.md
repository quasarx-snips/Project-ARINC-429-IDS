# Project-ARINC-429-IDS

Researching a software-based IDS for legacy ARINC 429 avionics. We use Shannon Entropy to detect data injection and spoofing attacks. By analyzing bitstream statistical anomalies, this zero-hardware solution provides a lightweight security layer for connected aircraft without breaking legacy compatibility.

## Why this research?
Modern aircraft are no longer "air-gapped." With the rise of SATCOM gateways and electronic flight bags, there are new ways for attackers to reach the internal ARINC 429 bus. Since this protocol has no built-in authentication, we are exploring how to detect "fake" data using math instead of new hardware.

## Our Approach
We are testing if **Shannon Entropy** can catch these attacks. Legitimate flight data (like altitude) follows a predictable, low-entropy pattern. An injection attack usually introduces "statistical noise" that we can detect.
* **Physical Layer:** We monitor the Bipolar Return-to-Zero (BPRZ) timing and the "Null" states.
* **Data Layer:** We calculate entropy on a sliding window of 32-bit words, specifically focusing on Label 030 (Altitude).

## Project Structure
We are keeping a daily log of our work to show how our research evolves over this 14-day sprint.
* `/logs`: Our daily research journals and observations.
* `/docs`: Technical notes on BPRZ and ARINC 429 specs.
* `/src`: The Python-based entropy engine (Development starts June 1).

## The Team
* **Bibhab:** Research Lead (Focusing on the physics and threat models).
* **Arnab:** Development Lead (Focusing on the data structures and coding - starting June 1).

---
*This repository is a work-in-progress for a formal research study (May 29 - June 14, 2026).*
