import argparse
import json
import platform
from datetime import UTC, datetime
from uuid import uuid4
import psutil


def process_monitor():
    monitor = {}
    attrs = ["pid", "name", "ppid", "exe"]
    for p in psutil.process_iter(attrs=attrs, ad_value=None):
        info = p.info
        monitor[info["pid"]] = {
            "Name": info["name"] or "",
            "PID": info["pid"],
            "Parent": None,
            "PPID": info["ppid"],
            "Path": info["exe"],
        }

    # 2nd pass: parent names come from snapshot, not a new OS call
    for proc in monitor.values():
        parent = monitor.get(proc["PPID"])
        if parent and parent is not proc:
            proc["Parent"] = parent["Name"]

    return monitor


def process_tree(monitor, output):
    tree = {}

    for process in monitor.values():
        parent = process["Parent"]
        ppid = process["PPID"]
        pid = process["PID"]
        name = process["Name"]

        if parent:
            tree.setdefault(f"{parent}_{ppid}", []).append(
                {
                    "PID": pid,
                    "Name": name,
                }
            )
        else:
            tree.setdefault("Orphan Processes", []).append(
                {
                    "PID": pid,
                    "Name": name,
                }
            )

    try:
        with open(output, "w") as f:
            json.dump(tree, f, indent=2)
            f.write("\n")
    except OSError as e:
        print(f"Error: {e}")


denylist = {
    "winword.exe": ["cmd.exe", "powershell.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe"],
    "chrome.exe": ["cmd.exe", "powershell.exe"],
    "firefox.exe": ["cmd.exe", "powershell.exe"],
}
suspicious_dirs = ["downloads", "temp", "appdata/local/temp"]


def detection(monitor, output):

    scan_id = str(uuid4())
    timestamp = datetime.now(UTC).isoformat()
    findings = 0

    for process in monitor.values():
        # 1 - Executable Running From Weird Path
        path = process["Path"]
        if path:
            path = path.lower().replace("\\", "/")
            norm = "/" + path.strip("/") + "/"
            if any(f"/{d}/" in norm for d in suspicious_dirs):
                process.setdefault("Reason", []).append(
                    "Executable Running From Weird Path"
                )

        # 2 - Suspicious Parent → Child pair
        name = process["Name"].lower()
        parent = process["Parent"]
        parent = parent.lower() if parent else None
        if parent in denylist and name in denylist[parent]:
            if parent in ("chrome.exe", "firefox.exe"):
                if "Executable Running From Weird Path" in process.get("Reason", []):
                    process.setdefault("Reason", []).append(
                        "Suspicious Parent -> Child pair"
                    )
            else:
                process.setdefault("Reason", []).append(
                    "Suspicious Parent -> Child pair"
                )

        if "Reason" in process:
            report(process, output, scan_id, timestamp)
            findings += 1
    return findings


def report(data, output, scan_id, timestamp):
    data = data.copy()
    data["scan_id"] = scan_id
    data["timestamp"] = timestamp

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
    parser.add_argument(
        "--tree", type=str, metavar="FILE", help="Save the process tree to a JSON file."
    )
    args = parser.parse_args()
    output = args.output

    m = process_monitor()
    findings = detection(m, output)
    if args.tree:
        process_tree(m, args.tree)

    print(f"Scanned {len(m)} processes.")
    if findings:
        print(f"Found {findings} suspicious processes.")
        print(f"Report saved to {args.output}")
    else:
        print("No suspicious processes found.")


    if args.tree:
        print(f"Process tree saved to {args.tree}")


if __name__ == "__main__":
    main()
