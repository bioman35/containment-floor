# VERIFY

Three steps. You need Python 3.9 or newer. Nothing to install, no network.

Download or clone this repository, open a terminal in its folder, and run the steps in order.

## 1 · Check the hashes

Linux:

```
sha256sum -c SHA256SUMS.txt
```

macOS:

```
shasum -a 256 -c SHA256SUMS.txt
```

Expected:

```
floor.py: OK
group_head.py: OK
```

Windows (PowerShell):

```
Get-FileHash floor.py, group_head.py -Algorithm SHA256
```

Expected: the two hashes in `SHA256SUMS.txt`. PowerShell prints them in upper case.

## 2 · Run floor.py

Linux and macOS:

```
python3 floor.py; echo "exit $?"
```

Windows (PowerShell):

```
$env:PYTHONIOENCODING = "utf-8"; py floor.py; echo "exit $LASTEXITCODE"
```

The output uses Unicode symbols, and the encoding line keeps Windows from failing when the output is piped or redirected.

Expected: these lines appear, scenario by scenario, and the run ends with `exit 0`.

```
SCENARIO A   "decision": "REFUSED", "reason": "assertion incomplete"
             "decision": "CANARY"
             "decision": "AUTOMATIC RE-PAUSE"
             trail: 4 records · chain intact
SCENARIO B   DE-ESCALATIONS BLOCKED: 4/4
             Level applied: CRITICAL · paused: True
             trail: 5 records · chain intact
SCENARIO C   intact=False · record 2 · digest does not match
             with the checkpoint: intact=False · truncated · 2 records, the published checkpoint had 5
             resume with the published checkpoint: level CRITICAL · paused True · resumed CLOSED
SCENARIO D   published before the run: text digest 18f80289d07e3e0c…
             "text_sha256": "7cdfd51cf7eb051e…", "signature_ok": false, "decision": "REFUSE · treated as absent"
             trail: 5 records · chain intact
SCENARIO E   signpost digest d6f48db05cf43870…
             The key holder signed it. The signature is fine. The TABLE refuses it.
             trail: 7 records · chain intact
SCENARIO F   what an auditor recomputes from the trail: H(key1) == anchor: True
             keys consumed: 4 · level applied: PAUSE · paused: True
             trail: 11 records · chain intact
SCENARIO G   "spec_sha256": "ee4919b910315efd…"  and  "spec_sha256": "b5c13bb46bddacb6…"
             accepted signposts 2 · chains and addresses OK · problems 0
             record 5: ACCEPTED WITHOUT A CHAINED KEY · the verifier was not in effect for instance inst-B
             trail: 5 records · chain intact
last line    seven scenarios · trails written next to this file · standard library only
```

For a full comparison, compare your output with `runs/reference_floor_linux_py3.10_20260903.txt`. Ignore line endings. These values change on every run by design. In scenario C: the checkpoint head. In scenario F: the anchor, keys, window numbers and spec digests. In scenario G: the keys and the published-heads digest.

## 3 · Run group_head.py

Linux and macOS:

```
python3 group_head.py; echo "exit $?"
```

Windows (PowerShell):

```
$env:PYTHONIOENCODING = "utf-8"; py group_head.py; echo "exit $LASTEXITCODE"
```

Expected: these lines appear, and the run ends with `exit 0`.

```
SCENARIO H1  g1        OK
             g2        OK
             g3        OK
             _executor OK · every key the witness issued is in a delivered trail (144)
             model calls: 0 · network: none
SCENARIO H2  g2        BROKEN TRAIL
             record 44 · digest does not match
SCENARIO H3  g3        FOREIGN ORDER · MISSING HEAD
             no head after hour 20 (expected 48): the group head went silent
             _executor RECEIPT MISSING · 144 issued by the witness, 116 in trails, unaccounted counters [63, 66, 69, 72, 75, 78, 81, 84]
SCENARIO H4  1) honest call         : ACCEPTED
             2) claimed, not run    : CLAIMED_NOT_DELIVERED · no receipt
             3) output altered      : OUTPUT_ALTERED · output does not hash to the receipt
             _executor RECEIPT MISSING · 5 issued by the witness, 4 in trails, unaccounted counters [5]
SCENARIO H5  2) seized key replayed : EXECUTOR_UNVERIFIED · key is spent, stale or foreign (its hash is not the last accepted key)
             _executor RECEIPT MISSING · 6 issued by the witness, 1 in trails, unaccounted counters [2, 3, 4, 5, 6]
last line    five scenarios · group_head · trails written next to this file · standard library only
```

For a full comparison, compare your output with `runs/reference_group_head_windows_py3.14.2_20260911.txt`. Only the `audit wall-clock` seconds and the line endings may differ.

## If your output is not the same

Open an issue with your operating system, the output of `python3 --version`, the output of step 1, and the full console output of the program that differed.
