![Layer: Data](https://img.shields.io/badge/Layer-Data-green)
![Encoding: BNR%20%2F%20BCD](https://img.shields.io/badge/Encoding-BNR%20%2F%20BCD-yellow)
![Word Size: 32--bit](https://img.shields.io/badge/Word%20Size-32--bit-blueviolet)
# Technical Note: ARINC 429 Physical Layer & Media Specifications

## Overview
To build an effective IDS, we first had to define the physical boundaries of the "Normal" environment. Based on the technical specifications provided by AIM GmbH [1], the ARINC 429 bus operates on a specific hardware profile that influences signal integrity.

## Cable & Impedance Characteristics
The transmission bus utilizes a **78 $\Omega$ shielded twisted pair cable**. During our research, we noted several critical constraints:
* **Grounding:** The shield must be grounded at both ends and at every junction. For our IDS, any compromise in grounding could lead to noise that could be mistaken as intrusion. 
* **Transmitter Impedance:** The source output is balanced at $75 \Omega \pm 5 \Omega$, divided equally between Line A and Line B.
* **Receiver Impedance:** The sink must maintain an effective input impedance of at least **$8k \Omega$** (Grounding in an aircraft refers to connecting it to the airframe, which is at neutral potential).

## Signal Levels
The Bipolar Return-to-Zero (BPRZ) waveform is the heartbeat of this system. The differential voltage ($V_A - V_B$) defines the logic:
* **High (Logic 1):** $+10V \pm 1V$
* **Null:** $0V \pm 0.5V$
* **Low (Logic 0):** $-10V \pm 1V$

**Project Impact:** Our IDS assumes that an attacker pivoting through a gateway (like a SATCOM unit) will be injecting digital words. However, if the injection hardware doesn't perfectly match these $\Omega$ ratings, we might see physical layer anomalies alongside the statistical ones. We also measure the BPRZ timings to check for entropy. Any minor entropy is detected as an intrusion.

## References
[1] AIM GmbH, "ARINC 429 Tutorial," Online Technical Manual, 2019.
