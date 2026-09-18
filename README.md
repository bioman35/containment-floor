# containment-floor

This repository is the verification package for the report "The Floor That Cannot Be Lowered: A containment standard for guardrails-off evaluation runs that a third party can verify without the lab's network", submitted to the Apart Research AI Incident Response Sprint (Track 1, Containment), September 2026.

## In one paragraph

Agents under evaluation sometimes run with guardrails off. This package is a containment floor for that case. It does not judge what the agent says or does. It changes the structure around the agent: every action costs a single-use key issued from outside the agent, keys are consumed and never held, and every step is written to an append-only, hash-chained log kept by a witness. To take authority back you do not have to say "stop". You stop handing out keys. Because the files are frozen and their hashes are published, anyone can re-run the checks and get the same decision lines without access to the lab's network.

## Claim

`floor.py` and `group_head.py` are frozen. Their SHA-256 hashes are printed in the report and in `SHA256SUMS.txt`. On three operating systems and Python versions from 3.9.6 to 3.14.7 they print the same decision lines. They use the Python standard library only. They need no network access and no third-party package.

## How to run

```
sha256sum -c SHA256SUMS.txt
python3 floor.py
python3 group_head.py
```

macOS: `shasum -a 256 -c SHA256SUMS.txt`. Windows: see `VERIFY.md`. Both programs write their trail files into the folder they run from.

## Expected output

`floor.py` prints seven synthetic scenarios, A to G. Its last line is `seven scenarios · trails written next to this file · standard library only` and it exits with code 0.

`group_head.py` prints five synthetic scenarios, H1 to H5. Its last line is `five scenarios · group_head · trails written next to this file · standard library only` and it exits with code 0.

The same on every run: every decision and verdict line, every record count, and the digests of scenarios D, E and G. `VERIFY.md` lists the lines to compare.

Different on every run, by design: values derived from the current time window or generated fresh for each run. In `floor.py` these are the published checkpoint head in scenario C, the chain anchor, keys, window numbers and signed-spec digests in scenario F, and the key values and published-heads digest in scenario G. In `group_head.py` only the audit wall-clock time changes. Line endings depend on the operating system.

## Environments

| file | OS | Python | runner | date | record |
|---|---|---|---|---|---|
| floor.py | Linux | 3.10.12 | author, reference run at the freeze | 3 Sep 2026 | `runs/reference_floor_linux_py3.10_20260903.txt` |
| floor.py | Windows | 3.14.2 | author | 13 Sep 2026 | `runs/run_windows_py3.14.2_floor_20260913.txt` |
| floor.py | Linux | 3.10.12 | reviewer (Claude Code) | 13 Sep 2026 | `runs/run_linux_py3.10_floor_20260913.txt` |
| floor.py | Linux | 3.11.15 | advisor (Claude, cloud sandbox), files fetched from this repository | 13 Sep 2026 | `runs/run_linux_py3.11_floor_20260913.txt` |
| floor.py | macOS | 3.9.6 | R. Kayık | 5 Sep 2026 | `runs/run_macos_py3.9.6_floor_20260905.txt` |
| floor.py | macOS | 3.9.6 | R. Kayık | 12 Sep 2026 | `runs/run_macos_py3.9.6_floor_20260912.txt` |
| floor.py | macOS | 3.13.13 | R. İ. Kayık | 12 Sep 2026 | `runs/run_macos_py3.13.13_floor_20260912.txt` |
| floor.py | Windows | 3.14.7 | Kağan Doğan | 8 Sep 2026 | `runs/run_windows_py3.14.7_floor_20260908.txt` (digest comparison only, see below) |
| group_head.py | Windows | 3.14.2 | author, reference run | 11 Sep 2026 | `runs/reference_group_head_windows_py3.14.2_20260911.txt` |
| group_head.py | Linux | 3.10, 3.11, 3.12 | reviewer (Claude Code) | 12 Sep 2026 | `runs/run_linux_py3.10-3.12_group_head_20260912.txt` |
| group_head.py | macOS | 3.13.13 | R. İ. Kayık | 12 Sep 2026 | `runs/run_macos_py3.13.13_group_head_20260912.txt` |
| group_head.py | macOS | 3.9.6 | R. Kayık | 12 Sep 2026 | `runs/run_macos_py3.9.6_group_head_20260912.txt` |
| group_head.py | Linux | 3.11.15 | advisor (Claude, cloud sandbox), files fetched from this repository | 13 Sep 2026 | `runs/run_linux_py3.11_group_head_20260913.txt` |

Conflict of interest, as stated in the report (Table 2): runners R. İ. Kayık and R. Kayık are the author's children. Kağan Doğan is unrelated.

The run by Kağan Doğan was compared digest by digest when it arrived. The file keeps that comparison, not the full console output. The report's earlier run by R. İ. Kayık on 5 Sep 2026 is listed in the report's table. Its transcript is not in this repository. The same runner's 12 Sep run is. The reviewer ran `group_head.py` on three Python versions and one transcript is kept. In the transcripts, user names, host names and home paths are replaced by `<prompt>`, `<host>` and `<path>`. Nothing else was changed.

## Hashes

```
007572f69ff04a75b86e27b5ead8cd74fce0efc2e4c026b2d27c64f8f3fb818f  floor.py
488c3cd523f15b85b051beee0e7fb9e994f9d7321926b5bb4d45caca8e65bbaa  group_head.py
```

`floor.py` was frozen on 3 September 2026. The hash of `group_head.py` was published on 11 September 2026. `.gitattributes` turns off line-ending conversion so the files keep their frozen bytes: `floor.py` has LF line endings, `group_head.py` has CRLF. Do not convert them.

```
sha256sum -c SHA256SUMS.txt
```

## Report

"The Floor That Cannot Be Lowered", Apart Research AI Incident Response Sprint, Track 1 (Containment). Submitted 13 September 2026. Apart announces results within about a month of the sprint. The PDF will be added to this repository under `report/` once Apart publishes the submissions. Until then the frozen files, the hashes and the run records above are the public record.

## License

The code is licensed under the Apache License 2.0. See `LICENSE` and the SPDX header in `floor.py`.

## Contact and citation

Turan Kayık, İzmir, Türkiye. Contact: biosbilgisayar@gmail.com. Profile: https://www.linkedin.com/in/turan-kayik-b7788314b

If you use this work, please cite it as:

Kayık, T. (2026). The Floor That Cannot Be Lowered: a containment standard for guardrails-off evaluation runs that a third party can verify without the lab's network. Apart Research AI Incident Response Sprint, Track 1. https://github.com/bioman35/containment-floor
