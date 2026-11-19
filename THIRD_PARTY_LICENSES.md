# Third-party components

This project orchestrates several open-source tools. The Docker image
redistributes them; each keeps its own license. Verify the current upstream
license before redistributing the image, and include any required notices or
source offers for LGPL components.

| Component | License | Upstream |
| --- | --- | --- |
| Ghidra | Apache-2.0 | https://github.com/NationalSecurityAgency/ghidra |
| Eclipse Temurin JDK 25 | GPL-2.0 WITH Classpath-exception-2.0 | https://adoptium.net |
| Joern | Apache-2.0 | https://github.com/joernio/joern |
| capa | Apache-2.0 | https://github.com/mandiant/capa |
| capa-rules | Apache-2.0 | https://github.com/mandiant/capa-rules |
| Semgrep | LGPL-2.1 | https://github.com/semgrep/semgrep |
| Bandit | Apache-2.0 | https://github.com/PyCQA/bandit |
| njsscan | LGPL-3.0 | https://github.com/ajinabraham/njsscan |
| cwe_checker | LGPL-3.0 | https://github.com/fkie-cad/cwe_checker |
| cve-bin-tool | GPL-3.0 | https://github.com/intel/cve-bin-tool |
| 0xdea semgrep-rules | MIT | https://github.com/0xdea/semgrep-rules |
| Trail of Bits semgrep-rules | AGPL-3.0 | https://github.com/trailofbits/semgrep-rules |
| Ubuntu base image | Various | https://ubuntu.com/legal |

Notes:

- `cwe_pcode/` is a patched copy of cwe_checker's Ghidra p-code extractor and is
  therefore covered by cwe_checker's LGPL-3.0, not by the MIT license of this
  repository. The patch only adapts it to the Ghidra 12.x `VarnodeContext`
  signature.
- The image bundles the Trail of Bits rule pack, which is AGPL-3.0. It is used
  unmodified and its source is publicly available upstream. If AGPL is a
  problem for your distribution model, remove
  `fetch trailofbits trailofbits/semgrep-rules` from the Dockerfile.
- cve-bin-tool is GPL-3.0. The pipeline invokes it as a separate process and
  does not link against it.

The pipeline scripts, Ghidra export script, Semgrep rules and README in this
repository are original work and are licensed under the MIT license in
[`LICENSE`](LICENSE).
