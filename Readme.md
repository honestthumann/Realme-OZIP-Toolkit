# Ultimate Oppo/Realme OZIP Toolkit & Unbricker

A powerful Python toolkit designed to decrypt Oppo and Realme `.ozip` firmware files, generate custom firmware-only flashable ZIPs, and safely flash raw `.ofp` files via Fastboot to recover hard-bricked devices.

**Author:** Honestt_Humann

## Features
* **OZIP Decryption:** Instantly strips AES-128-ECB encryption from official Oppo/Realme OTA packages, converting them into standard `.zip` files.
* **Smart Firmware ZIP Builder:** Automatically parses decrypted firmware, extracts low-level partitions (modem, bootloader, dsp), and rewrites the `updater-script` to create a tiny "Firmware-Only" flashable ZIP. Perfect for Custom ROM users who need to update their base without losing data.
* **OFP Fastboot Flasher:** A mathematically corrected `flash.py` script that utilizes true AES-CFB decryption to safely flash factory `.ofp` files. Includes automated `.img` chunk merging for dynamic `super` partitions.

## Installation

1. Clone this repository:
   ```bash
   git clone 
   cd Realme-OZIP-Toolkit