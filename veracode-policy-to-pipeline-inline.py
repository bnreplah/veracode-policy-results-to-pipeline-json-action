import json
import argparse
from veracode_api_py import Applications, Findings, Sandboxes

BASE_RESULTS_JSON = {
    "_links": {},
    "scan_id": "",
    "message": "",
    "modules": [],
    "modules_count": 0,
    "findings": [],
    "selected_modules": []
}

BASE_FINDING_JSON = {
    "flaw_match": {},
    "stack_dumps": {
        "stack_dump": []
    },
    "flaw_details_link": ""
}


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch Veracode findings")

    parser.add_argument("--app-name", required=True, help="Application name")
    parser.add_argument("--sandbox-name", required=False, help="Sandbox name")
    parser.add_argument(
        "--output-file",
        default="results.json",
        help="Output file name (default: results.json)"
    )
    # parser.add_argument("--vid", required=False, help="Veracode API ID")
    # parser.add_argument("--vkey", required=False, help="Veracode API KEY")
    return parser.parse_args()


def main():
    args = parse_args()

    application_name = args.app_name
    sandbox_name = args.sandbox_name
    output_file = args.output_file
    
    # Find application
    candidates = Applications().get_by_name(application_name)
    if not candidates:
        raise ValueError(f"No application found for {application_name}")

    selected_application = None
    for app in candidates:
        if app['profile']["name"].lower() == application_name.lower():
            selected_application = app
            break

    if not selected_application:
        selected_application = candidates[0]

    application_guid = selected_application['guid']
    print(f"Using application: {selected_application['profile']['name']}")

    # Sandbox selection
    selected_sandbox_guid = None
    if sandbox_name:
        sandboxes = Sandboxes().get_all(application_guid)
        for sandbox in sandboxes:
            if sandbox["name"] == sandbox_name:
                selected_sandbox_guid = sandbox["guid"]
                break

    print("Fetching findings...")
    findings = Findings().get_findings(
        application_guid,
        sandbox=selected_sandbox_guid
    )

    results_json = BASE_RESULTS_JSON.copy()

    for finding in findings:
        f = BASE_FINDING_JSON.copy()
        fd = finding["finding_details"]

        f.update({
            "title": fd["attack_vector"],
            "issue_id": finding["issue_id"],
            "image_path": fd["file_path"],
            "gob": "B",
            "severity": fd["severity"],
            "issue_type_id": "taint",
            "issue_type": fd["cwe"]["name"],
            "cwe_id": str(fd["cwe"]["id"]),
            "exploit_level": str(fd["exploitability"]),
            "display_text": finding["description"],
            "files": {
                "source_file": {
                    "file": fd["file_path"],
                    "upload_file": fd["file_path"],
                    "line": fd["file_line_number"],
                    "function_name": fd["procedure"].split(".")[-1],
                    "qualified_function_name": fd["procedure"],
                    "function_prototype": fd["procedure"],
                    "scope": fd["file_path"].split(".")[0].replace("/", ".")
                }
            }
        })

        results_json["findings"].append(f)

    with open(output_file, "w") as f:
        json.dump(results_json, f)

    print(f"Results saved → {output_file}")


if __name__ == "__main__":
    main()