# Third-party components

This project orchestrates several open-source tools. The Docker image
redistributes them; each keeps its own license. Verify the current upstream
license before redistributing the image, and include any required notices or
source offers for LGPL components.

| Component | License | Upstream |
| --- | --- | --- |
| Ghidra | Apache-2.0 | https://github.com/NationalSecurityAgency/ghidra |
| Joern | Apache-2.0 | https://github.com/joernio/joern |
| capa | Apache-2.0 | https://github.com/mandiant/capa |
| Semgrep | LGPL-2.1 | https://github.com/semgrep/semgrep |
| cwe_checker | LGPL-3.0 | https://github.com/fkie-cad/cwe_checker |
| cve-bin-tool | LGPL-3.0 | https://github.com/intel/cve-bin-tool |
| Ubuntu base image | Various | https://ubuntu.com/legal |

The pipeline scripts, Ghidra export script, Semgrep rules and README in this
repository are original work and are licensed under the MIT license in
[`LICENSE`](LICENSE).
