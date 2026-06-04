import psutil
import json
import argparse

def process_monitor():
    monitor={}
    for p in psutil.process_iter():
        try:
            monitor[p.pid] = {
                "Name": p.name(),
                "PID": p.pid,
                "Parent": p.parent().name() if p.parent() else None,
                "PPID": p.ppid(),
                "Path": p.exe()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return monitor

def process_tree(monitor):
    tree = {}
    for pid, process in monitor.items():
            parent = process['Parent']
            ppid = process['PPID']
            name = process['Name']
            if parent:
                tree.setdefault(f"{parent}_{ppid}", []).append(name)
            else:
                tree.setdefault("Orphan Processes", []).append(name)
        
    # Process Tree File
    try:
        with open("process_tree.jsonl", "w") as f:
            json.dump(tree, f)
            f.write("\n")   
    except OSError as e:
        print(f"Error: {e}")

denylist= {
    "winword.exe": ["cmd.exe", "powershell.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe"],
    "chrome.exe": ["cmd.exe", "powershell.exe"],
    "firefox.exe": ["cmd.exe", "powershell.exe"]
}
suspicious_dirs = [
    "downloads", 
    "temp",
    "appdata/local/temp"
]

def detection(monitor, output):
    for pid, process in monitor.items():
        #1 - Executable Running From Weird Path
        path = process['Path']
        if not path: continue
        path = path.lower()
        path = path.replace("\\", "/")
        if any(d in path for d in suspicious_dirs):
            process.setdefault("Reason", []).append("Executable Running From Weird Path")
            break

        #2 - Suspicious Parent → Child pair
        name = process['Name'].lower()
        parent = process['Parent'].lower()
        if parent in denylist and name in denylist[parent]:
            if parent in ("chrome.exe", "firefox.exe"):
                if "Executable Running From Weird Path" in process.get("Reason", []):
                    process.setdefault("Reason", []).append("Suspicious Parent -> Child pair")
            else:
                process.setdefault("Reason", []).append("Suspicious Parent -> Child pair")
        
        if "Reason" in process:  
            report(process, output) 
        
def report(data, output):
    try:
        with open(output, "a") as f:
            json.dump(data, f)
            f.write("\n")   
    except OSError as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Process Behavior Monitor")
    parser.add_argument("--output", type=str, default="report.jsonl")
    args = parser.parse_args()
    output = args.output

    m = process_monitor()
    detection(m, output)
    process_tree(m)

if __name__ == "__main__": 
    main()