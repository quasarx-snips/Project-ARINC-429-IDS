# Technical Note: The "Label Flip" & Word Structure

## The 32-Bit Word Challenge
While the ARINC 429 word is technically 32 bits, the way those bits are handled is non-linear. This "Transmission Order Anomaly" was a primary hurdle in developing our Python decoder.

## Bit Mapping
According to the standard word format [1][2], the fields are laid out as follows:
* **Bits 1–8:** Label (The data identifier)
* **Bits 9–10:** SDI (Source/Destination Identifier)
* **Bits 11–29:** Data Payload (BNR or BCD format)
* **Bits 30–31:** SSM (Sign/Status Matrix)
* **Bit 32:** Parity (Odd parity)

## The "Label Flip" Observation
The most confusing part of the protocol is that while bits 9 through 32 are transmitted **Least Significant Bit (LSB) first**, the **Label (Bits 1–8)** is transmitted **Most Significant Bit (MSB) first**.

## Conversion from Binary Data
The binary data is converted to decimal which is further converted into octal labels. The octal values are later processed further to match it with the metadata.

## Implementation Logic:

In our `decoder.py`, we had to implement a deterministic bit-reversal specifically for the first 8 bits. Without this "flip," a Label 014 (Radio Height) would incorrectly appear as Label 200. 


```python

label_bits = sample[-8:][::-1] # Reversing the first 8 bits to get the octal bits
octal_bit = oct(int(label_bits, 2)) # Converting the binary value to octal values
final_output = octal_bit[2:].zfill(3) # Removes the first two characters 0o and fills zero upto 3 possible places
```
