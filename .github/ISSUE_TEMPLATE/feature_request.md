---
name: Feature request
about: Suggest a new detection logic or protocol feature
title: ['Feature']
labels: ['Enhancement', 'Entropy-Math']
assignees: ''
---

**Is your feature request related to a problem? Please describe.**
A clear description of the security gap we are filling (e.g., *"Currently, we don't have a baseline for Label 014 (Magnetic Heading), making it vulnerable to rotation-based injection attacks"*).

**Describe the solution you'd like**
A description of the new logic or math you want to implement. 
* **Target Label:** (e.g., 014)
* **Detection Method:** (e.g., Shannon Entropy, Delta-Check, or Parity Monitoring)

**Technical Specifications (The "Physics" Logic)**
* **Normal Behavior:** (e.g., *"Heading should not change more than 5 degrees per 100ms window"*)
* **Entropy Threshold:** (What is the target $H(X)$ value for an alert?)
* **Bit Range:** (e.g., Bits 11-29 for BNR data)

**Describe alternatives you've considered**
Did you consider a simpler check? (e.g., *"We considered a simple range check, but Shannon Entropy is better for detecting subtle 'low-and-slow' injection attacks"*).

**Additional context**
Link to specific pages in the `AIT_ARINC429.pdf` or `AIM_Online_ARINC429.pdf` or your research logs that justify this feature.
