# ⚠️ CRITICAL SAFETY NOTICE — TEST HARNESS & SIMULATION SCRIPTS

> **IMPORTANT**: The scripts in this directory are **inert behavioral simulations** designed solely to test the detection pipeline, event correlation, and risk scoring logic of DefenceIQ.

---

### Mandatory Testing Rules

1. **NO REAL MALWARE EVER**  
   Never place, embed, or test real malware samples or weaponized exploits in this repository. All simulations use inert, benign operations (e.g. creating dummy text files, launching benign built-in calculators or dummy PowerShell echo commands).

2. **ISOLATED VM ENVIRONMENT ONLY**  
   Always run test scenarios inside a disposable, isolated Virtual Machine (e.g., Hyper-V, VirtualBox, or VMware snapshot).  
   **DO NOT RUN SIMULATION SCRIPTS ON YOUR PRIMARY HOST WORKSTATION.**

3. **CLEAN SNAPSHOTS**  
   Take a clean snapshot of your test VM before executing any test scenarios. Revert to the snapshot upon completion.

4. **REVERSIBLE OPERATIONS**  
   All simulation scripts must only touch temporary directories (such as `test_sandbox/` or `%TEMP%\defenceiq_test`) and clean up any created artifacts upon termination.
