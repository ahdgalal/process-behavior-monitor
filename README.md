# Process Behavior Monitor


A behavioral process monitor that flags suspicious processes by parent child relationships and execution path, not by name. Built to catch malware disguised as legitimate processes.

## The Problem

Malware renames itself to look legit (svch0st.exe), so name-based detection fails; behavior doesn't lie.

## Installation & Usage

```bash
pip install psutil
python process_monitor.py
```
Note: needs admin privileges to see all processes

## Example output

```json
{"Name": "powershell.exe", "PID": 3099, "Parent": "winword.exe", "PPID": 2201, "Path": "C:\\Program Files\\Microsoft Office\\Word\\WINWORD.EXE", "Reason": ["Suspicious Parent -> Child pair"]}
{"Name": "cmd.exe", "PID": 4120, "Parent": "chrome.exe", "PPID": 1988, "Path": "C:\\Users\\Bob\\AppData\\Local\\Temp\\cmd.exe", "Reason": ["Executable Running From Weird Path", "Suspicious Parent -> Child pair"]}
```
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

## Future work


- The rules can be made in an external file later in further versions
- Code-signature verification to cut temp false positives
- More rules will be added
