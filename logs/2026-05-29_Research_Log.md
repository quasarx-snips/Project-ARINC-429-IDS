# Research Log: May 29, 2026
**Researcher:** Bibhab
**Topic:** ARINC 429 Physical Layer & Security Entry Points

## 1. Observations on BPRZ Signaling
After reviewing the protocol fundamentals and the AIM technical manual, I focused on the Bipolar Return-to-Zero (BPRZ) encoding. 

**Key Technical Takeaways:**
* The bus uses three distinct states: High (+10.0 V ± 1.0 V ), Low (-10.0 V ± 1.0 V ), and a Null state (0 V ± 0.5V).
* I noticed that the "Return-to-Zero" part is the most critical for our IDS. Because the signal must hit ‹‹LI››0V‹‹/LI›› halfway through every bit, the receiver doesn't need a separate clock wire. 
* **Project Impact:** This "self-clocking" nature means if an attacker tries to inject data and messes up the timing even slightly, the receiver will lose sync. This is a physical vulnerability we can monitor.

## 2. Analysis of the "Gateway Pivot" (Santamarta Research)
I watched the Ruben Santamarta Black Hat talk, specifically focusing on the segment regarding aviation network domains.

**My Analysis:**
The "air-gap" in modern aircraft is largely a myth. While the ARINC 429 bus itself is isolated, it connects to "Gateways" (like the Aircraft Interface Device or SATCOM units). 
* Santamarta showed that if an attacker compromises the SATCOM firmware (which often has hard-coded credentials), they can "pivot" into the internal bus.
* Since ARINC 429 has no built-in authentication, once the attacker is "in" the gateway, they can send any 32-bit word they want.
* **Project Impact:** This justifies why we need a Shannon Entropy IDS. We can't stop the attacker from getting into the bus via a gateway, but we can detect the "statistical signature" of their injected data.

## 3. Next Steps
* Tomorrow (May 30), I will look into the specific structure of Label 030 (Altitude) to see how the bits are mapped.
* I need to prepare the logic rules for Arnab so he can start the data structure coding on June 1st.
