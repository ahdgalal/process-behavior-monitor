import psutil
import json
import argparse
import platform

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
    for process in monitor.values():
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
    for process in monitor.values():
        #1 - Executable Running From Weird Path
        path = process['Path']
        if path:
            path = path.lower().replace("\\", "/")
            norm = "/" + path.strip("/") + "/"
            if any(f"/{d}/" in norm for d in suspicious_dirs):
                process.setdefault("Reason", []).append("Executable Running From Weird Path")

        #2 - Suspicious Parent → Child pair
        name = process['Name'].lower()
        parent = process['Parent']
        parent = parent.lower() if parent else None
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
    if platform.system() != "Windows":
        print("Warning: detection rules are tuned for Windows.")

    parser = argparse.ArgumentParser(description="Process Behavior Monitor")
    parser.add_argument("--output", type=str, default="report.jsonl")
    args = parser.parse_args()
    output = args.output

    m = process_monitor()
    detection(m, output)
    process_tree(m)

    print(f"Scanned {len(m)} processes.")
    print(f"Report saved to {args.output}")

if __name__ == "__main__": 
    main()