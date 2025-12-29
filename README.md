# Automated-CIS-Hardening-Adversary-Emulation

This project demonstrates an automated security hardening and validation pipeline that combines **CIS Benchmark Hardening** with **MITRE ATT&CK–aligned adversary emulation**.

The goal is to move beyond static compliance by:
- Automatically enforcing CIS security baselines on Windows systems
- Validating the effectiveness of hardening through real adversary simulations
- Measuring security posture improvements before and after remediation

This work was developed as part of my MSc thesis in Cybersecurity.
 ---

## Prerequisites

### CIS Hardening

- **CIS-CAT Lite Assessor**
  - Tested with version **4.56.0**
  - Newer versions (4.57+) are currently not supported
- Relevant **CIS Benchmark** (PDF)
- **Python 3.x**
- **Windows target system** matching the CIS Benchmark version

---

### Adversary Emulation (MITRE Caldera)

- **MITRE Caldera**
  - Installed according to the official guide:
    https://github.com/mitre/caldera
- **Python 3.11**
  - Required due to compatibility issues with other versions
- One or more Caldera agents deployed on the target system
