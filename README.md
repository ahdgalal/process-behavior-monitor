# Process Behavior Monitor


A behavioral process monitor that flags suspicious processes by parent child relationships and execution path.

## The Problem

Malware renames itself to look legit (svch0st.exe), so name-based detection fails; behavior doesn't lie.

## Installation & Usage

```bash
pip install psutil
python process_monitor.py --output my_report.jsonl
```
Note: needs admin privileges to see all processes

## How It Flags Suspicious Processes


Two Rules:
- Rule 1: Weird Path Detection
- Rule 2: Suspicious Parent → Child Relationship

Special condition (browser protection gate): Browser pairs are a weak signal, so they only flag when the path is also suspicious as browsers legitimately spawn shells.

## Limitations


- Windows-only paths
- Legitimate installers/updaters run from temp and will false-positive
```json
{"Name": "CodeSetup.exe", "PID": 1740, "Parent": "Code.exe", "PPID": 5096, "Path": "C:\\Users\\User\\AppData\\Local\\Temp\\vscode-stable-user-x64\\CodeSetup-stable.exe", "Reason": ["Executable Running From Weird Path"]}
```
- The denylist covers only a handful of parent processes.
- Renamed executable detection: Parent child rules compare
  process names against a small denylist. For example, renaming
  `powershell.exe` to `notes.exe` can bypass the corresponding
  name based rule. The path rule may still flag it if it runs
  from a configured suspicious directory, but renamed executables
  in other locations may go undetected.


## Future work


- The rules can be made in an external file later in further versions
- Code-signature verification to cut temp false positives
- More rules will be added
