## 🛰 ARINC 429 Snippet Submission

**Description of Changes**
A brief summary of the logic added.

**Related Issue**
Fixes # (Link the Issue number here)

**Protocol Validation Checklist**
- [DONE] **Bit Mapping:** Verified against AIM Manual Page 13.
- [DONE] **Label Flip:** Bits 1-8 are reversed for correct octal decoding.
- [DONE] **Sign Bit:** Bit 29 logic handles Plus/Minus correctly.
- [DONE] **Parity:** Bit 32 Odd Parity check is implemented.
- [DONE] **Metadata:** `src/metadata.json` has been updated with new thresholds.

**Testing Performed**
- [DONE] Verified with a "Normal" 32-bit word.
- [UNDONE] Verified with a "Malicious" 32-bit word (Attack Vector).

**Logs**
```
~/workspace$ python test.py


{'label': '014',
  'name': 'Radio Height',
  'sdi':
      {'code': '00',
      'description': 'Source/Destination 0'},
  'data': 0, 
  'ssm': 
      {'code': '00',
      'description': 'Failure Warning'},
  'parity': '1'}
~/workspace$
```
