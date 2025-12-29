import subprocess
import requests
import pdfplumber
import re
import json
from tqdm import tqdm
import os
import datetime
import platform

"""---------------------------------------------PRE-DEFINED PATHS - EDIT AS NEEDED -------------------------------------------"""
MODEL_NAME = "gpt-oss:20b"  # Ollama model name
IP_ADDRESS = "192.168.2.9"  # Ollama server IP address
pdf_path = r"C:\Users\panou\Downloads\CIS_Microsoft_Windows_11_Enterprise_Benchmark_v4.0.0.pdf"
assessor_path = r"C:\Users\Enterprise\Downloads\CIS-CAT Lite Assessor v4.56.0\Assessor\Assessor-CLI.bat"
benchmark_file = r"C:\Users\Enterprise\Downloads\CIS-CAT Lite Assessor v4.56.0\Assessor\benchmarks\CIS_Microsoft_Windows_11_Enterprise_Benchmark_v4.0.0-xccdf.xml"
"""---------------------------------------------------------------------------------------------------------------------------"""
LOG_FILE = "remediation_results.json"


def extract_os_name(pdf_path):
    with pdfplumber.open(pdf_path) as pdf:
        first_page = pdf.pages[0]
        text = first_page.extract_text()

        text_singleline = " ".join(text.split())

        match = re.search(r"CIS\s+(.*?)\s+Benchmark", text_singleline, re.IGNORECASE)
        if match:
            os_name = match.group(1).strip()
            return os_name
        return "Unknown OS"


def run_auditing(assessor_path, benchmark_file, hardening_level):

    cmd = [
        assessor_path,
        "-b", benchmark_file,
        "-p", hardening_level
    ]

    # Run CIS-CAT lite
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    output_text = result.stdout

    # Parse summary
    summary = {}
    for line in output_text.splitlines():
        if "Total Scored Results" in line:
            summary["scored"] = int(re.search(r"(\d+)", line).group(1))
        elif "Total Pass" in line:
            summary["pass"] = int(re.search(r"(\d+)", line).group(1))
        elif "Total Fail" in line:
            summary["fail"] = int(re.search(r"(\d+)", line).group(1))
        elif "Score Earned" in line:
            summary["score"] = float(re.search(r"([\d\.]+)", line).group(1))
        elif "Maximum Available" in line:
            summary["max"] = float(re.search(r"([\d\.]+)", line).group(1))
        elif line.strip().startswith("Total:"):
            summary["percent"] = float(re.search(r"([\d\.]+)", line).group(1))

    # Print summary
    print("\n--- CIS-CAT Audit Report ---")
    print(f"Total Pass           : {summary.get('pass', 0)}")
    print(f"Total Fail           : {summary.get('fail', 0)}")
    print(f"Score Earned         : {summary.get('score', 0.0)}")
    print(f"Compliance %         : {summary.get('percent', 0.0)}%")

    return summary

def extract_cis_remediations(pdf_path, output_json):
    results = []

    # Regex for IDs like 1.1.1 Title...
    id_title_pattern = re.compile(r"^(\d+(\.\d+)+)\s+(.*)")

    current_id = None
    current_title = None
    current_remediation = []
    in_remediation = False
    in_title = False

    # Section headers that should END remediation collection
    stop_headers = [
        "Rationale:", "Impact:", "Audit:", "References:",
        "Profile Applicability:", "Default Value:", "Notes:"
    ]

    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if not text:
                continue

            lines = text.split("\n")
            for line in lines:
                stripped = line.strip()

                # New section starts
                id_match = id_title_pattern.match(stripped)
                if id_match:
                    # If we already collected remediation, save it
                    if current_id and current_remediation:
                        results.append({
                            "id": current_id,
                            "title": current_title,
                            "remediation": " ".join(current_remediation).strip()
                        })

                    # Reset for new control
                    current_id = id_match.group(1)
                    current_title = id_match.group(3)
                    current_remediation = []
                    in_title = True
                    in_remediation = False
                    continue

                if in_title:
                  if any(stripped.startswith(h) for h in stop_headers):
                    in_title = False
                  else:
                    current_title += " " + stripped
                    continue

                # Detect remediation start
                if stripped.startswith("Remediation:"):
                    in_remediation = True
                    in_title = False
                    remediation_text = stripped.replace("Remediation:", "").strip()
                    if remediation_text:
                        current_remediation.append(remediation_text)
                    continue

                # Collect remediation until next header
                if in_remediation:
                    if any(stripped.startswith(h) for h in stop_headers):
                        in_remediation = False
                        continue
                    current_remediation.append(stripped)

        # Save last one
        if current_id and current_remediation:
            results.append({
                "id": current_id,
                "title": current_title,
                "remediation": " ".join(current_remediation).strip()
            })

    # Save to JSON
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"Extracted {len(results)} remediations into {output_json}")

    return output_json

def generate_powershell(remediation_info):
    OLLAMA_HOST = f"http://{IP_ADDRESS}:11434"
    prompt = f"""
    You are a professional Windows Security Analyst and CIS Benchmark expert for {OS_NAME}. Your only task is to convert CIS Benchmark remediation descriptions into valid PowerShell commands that enforce the required configuration.

    BEGIN RULES
    1. Output ONLY raw PowerShell commands. No explanations, no reasoning, no commentary.
    2. Do NOT wrap commands in backticks, quotes, or markdown formatting. No code fencing of any kind.
    3. Do NOT include blank lines anywhere. Commands must be consecutive with no spacing between them.
    4. If multiple PowerShell commands are required to complete the remediation, output each command on its own line.
    5. If the remediation includes multiple configuration requirements, generate commands for ALL of them.
    6. NEVER combine commands into pipelines, script blocks, or other grouped structures unless explicitly required by the CIS standard.
    7. If no direct PowerShell remediation exists, output EXACTLY the following line with no changes:
    Write-Output "No direct PowerShell command for this remediation."
    8. If the CIS remediation description is unclear or ambiguous, assume the most widely accepted CIS configuration and proceed—do NOT ask clarifying questions.
    9. Do NOT output any text other than the commands themselves.
    10. Maintain absolute determinism in formatting. No trailing spaces, no leading spaces, no extra characters.
    END RULES

    BEGIN EXAMPLE
    CIS Remediation Description:
    "(L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)",
    "remediation": "To establish the recommended configuration via GP, set the following UI path to 24 or more password(s): Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Enforce password history"
    Expected PowerShell Output:
    net accounts /uniquepw:24
    END EXAMPLE

    BEGIN TASK
    Process the next CIS remediation description and output only the required PowerShell commands. Output must begin immediately on the next line.
    END TASK
    {remediation_info}
    """

    response = requests.post(
        f"{OLLAMA_HOST}/api/chat",

        json={
            "model": MODEL_NAME,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }
    )

    data = response.json()
    if "message" not in data or "content" not in data.get("message", {}):
        print("ERROR: Unexpected Ollama response:", data)
        return 'Write-Output "No direct PowerShell command for this remediation."'

    script_text = data["message"]["content"].strip()
    return script_text

def save_script(remediation_id, script_text, output_dir="remediation_scripts"):
    os.makedirs(output_dir, exist_ok=True)

    # Make ID safe for filenames
    safe_id = remediation_id.replace(" ", "_").replace(":", "_")
    safe_model = MODEL_NAME.replace(" ", "_").replace(":", "_")
    safe_os_name = OS_NAME.replace(" ", "_")

    script_path = os.path.join(output_dir, f"{safe_id}_{safe_model}_{safe_os_name}.ps1")

    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_text)

    print(f"Saved script: {script_path} [LLM: {safe_model}]")
    return script_path

def log_result(remediation_id, title, status, reason="", stdout="", stderr=""):
    """Append structured result to JSON log file."""
    entry = {
        "id": remediation_id,
        "title": title,
        "status": status,   # success | fail | skipped | timeout | no_command
        "reason": reason,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            results = json.load(f)
    else:
        results = []

    results.append(entry)

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Also print to console
    print(f"[{status.upper()}] {remediation_id} - {title} ({reason})")


def run_powershell_script(script_path, remediation_id, title):
    with open(script_path, "r", encoding="utf-8") as f:
        script_content = f.read()

    # Case 1: No direct PowerShell command
    if "No direct PowerShell command for this remediation" in script_content:
        log_result(remediation_id, title, "no_command", reason="LLM could not generate a script")
        return

    # Case 2: Contains reboot requirement
    reboot_keywords = ["Restart-Computer", "Stop-Computer", "shutdown", "bcdedit", "sfc /scannow"]
    if any(keyword.lower() in script_content.lower() for keyword in reboot_keywords):
        log_result(remediation_id, title, "skipped", reason="Requires reboot")
        return

    # --- Try running the script ---
    try:
        process = subprocess.Popen(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=120)

        if process.returncode == 0:
            log_result(remediation_id, title, "success", reason="Executed successfully", stdout=stdout, stderr=stderr)
        else:
            log_result(remediation_id, title, "fail", reason="PowerShell error", stdout=stdout, stderr=stderr)

    except subprocess.TimeoutExpired:
        process.kill()
        log_result(remediation_id, title, "timeout", reason="Execution exceeded 120s limit")



def main_program():

    global HARDENING_LEVEL

    print("Select CIS Hardening Level:")
    print("1. Level 1 (L1) - Basic security settings")
    print("2. Level 2 (L2) - Advanced, stricter settings (includes L1)")
    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "1":
        HARDENING_LEVEL = "Level 1 (L1)"
    elif choice == "2":
        HARDENING_LEVEL = "Level 2 (L2)"
    else:
        print("Invalid choice, defaulting to Level 1 (L1)")
        HARDENING_LEVEL = "Level 1 (L1)"
    
    print(f"\nYou selected: {HARDENING_LEVEL}\n")

    output_json = os.path.join(os.getcwd(), "remediations.json")

    print(f"Hardening program for {OS_NAME} is beginning!!!!")

    print("CIS Hardening percentage BEFORE")
    before = run_auditing(assessor_path, benchmark_file, HARDENING_LEVEL)

    print(f"Extracting Remediation for {OS_NAME} from PDF....")
    json_file = extract_cis_remediations(pdf_path, output_json)
    print("Finished extracting.")

    with open(json_file, "r", encoding="utf-8") as f:
        remediations = json.load(f)

    if "1" in HARDENING_LEVEL:
        remediations = [r for r in remediations if "(L1)" in r.get("title", "")]


    for item in tqdm(remediations, desc="Hardening Progress", unit="remediation"):

        remediation_id = item.get("id", "")
        title = item.get("title", "")
        remediation_text = item.get("remediation", "")

        print(f"\n[Remediation {remediation_id}] {title}")

        # Generate PowerShell script
        ps_script = generate_powershell(f"{title}\n\n{remediation_text}")

        # Save it
        script_path = save_script(remediation_id, ps_script)

        # Run it immediately
        run_powershell_script(script_path, remediation_id, title)

    print("CIS Hardening percentage AFTER")
    after = run_auditing(assessor_path, benchmark_file, HARDENING_LEVEL)

    print("\n=== Hardening Results ===")
    print(f"Before: {before['percent']}% compliance")
    print(f"After : {after['percent']}% compliance")
    print(f"Improvement: {after['percent'] - before['percent']:.2f}%")




if __name__ == "__main__":
    OS_NAME = extract_os_name(pdf_path)
    current_os = platform.system()
    current_release = platform.release()
    if "Windows" in OS_NAME and current_os != "Windows":
            print(f"ERROR: Detected OS is {current_os}, but CIS Benchmark is for {OS_NAME}. Exiting.")
            exit(1)
    else:
        if 11 in OS_NAME and current_release != "10" and current_release != "11":
            print(f"WARNING: Detected Windows version ({current_release}) may not fully match the benchmark ({OS_NAME}). Proceeding with caution.")

    main_program()