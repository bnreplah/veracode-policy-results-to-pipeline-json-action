from veracode_api_py import Applications, Findings, Sandboxes, applications
import pick
import json

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

def main():
    application_guid = None
    selected_application = None

    while application_guid is None:
        application_name = input("Enter the application you want to fetch (empty to quit): ").strip()
        if not application_name:
            break
        # Get the application GUID
        candidates = Applications().get_by_name(application_name)
        if candidates:
            for application in candidates:
                if application['profile']["name"].lower() == application_name.lower():
                    selected_application = application
                    application_guid = selected_application['guid']
                    print(f"Found application: {selected_application['profile']['name']} (GUID: {application_guid})")
                    break
            if application_guid:
                break

            print(f"Found {len(candidates)} potential applications:")
            option, index = pick.pick([application['profile']["name"] for application in candidates], "Select Application to Fetch", indicator='=>', default_index=0)
            selected_application = candidates[index]
            application_guid = selected_application['guid']
            print(f"Selected application: {option} (GUID: {application_guid})")
        else:
            print(f"No application found with name '{application_name}'.")

    sandboxes = Sandboxes().get_all(application_guid)

    if sandboxes:
        selected_sandbox = None
        option, index = pick.pick(["Yes", "No"], "Do you want to download sandbox data?", indicator='=>', default_index=0)
        if index == 0:
            option, index = pick.pick([sandbox["name"] for sandbox in sandboxes], "Select Sandbox to Fetch", indicator='=>', default_index=0)
            selected_sandbox = sandboxes[index]
            print(f"Selected sandbox: {option} (GUID: {selected_sandbox['guid']})")
    
    print("Fetching findings...")
    
    findings = Findings().get_findings(application_guid, sandbox=selected_sandbox['guid'] if selected_sandbox else None)

    print("Converting findings to pipeline JSON format...")
    results_json = BASE_RESULTS_JSON.copy()

    for finding in findings:
        findings_as_result = BASE_FINDING_JSON.copy()
        findings_as_result["title"] = finding["finding_details"]["attack_vector"]
        findings_as_result["issue_id"] = finding["issue_id"]
        findings_as_result["image_path"] = finding["finding_details"]["file_path"]
        findings_as_result["gob"] = "B"
        findings_as_result["severity"] = finding["finding_details"]["severity"]
        findings_as_result["issue_type_id"] = "taint"
        findings_as_result["issue_type"] = finding["finding_details"]["cwe"]["name"]
        findings_as_result["cwe_id"] = str(finding["finding_details"]["cwe"]["id"])
        findings_as_result["exploit_level"] = str(finding["finding_details"]["exploitability"])
        findings_as_result["display_text"] = finding["description"]
        
        findings_as_result["files"] = {}
        findings_as_result["files"]["source_file"] = {}
        findings_as_result["files"]["source_file"]["file"] = finding["finding_details"]["file_path"]
        findings_as_result["files"]["source_file"]["upload_file"] = finding["finding_details"]["file_path"]
        findings_as_result["files"]["source_file"]["line"] = finding["finding_details"]["file_line_number"]
        findings_as_result["files"]["source_file"]["function_name"] = finding["finding_details"]["procedure"].split(".")[-1]
        findings_as_result["files"]["source_file"]["qualified_function_name"] = finding["finding_details"]["procedure"]
        findings_as_result["files"]["source_file"]["function_prototype"] = finding["finding_details"]["procedure"]
        findings_as_result["files"]["source_file"]["scope"] = finding["finding_details"]["file_path"].split(".")[0].replace("/", ".")

        results_json["findings"].append(findings_as_result)

    print("Finished converting findings to pipeline JSON format.")
    file_name = input("Enter the file name to save the results (default: results.json): ").strip() or "results.json"
    
    with open(file_name, 'w') as f:
        json.dump(results_json, f)
    print(f"Results saved to {file_name}")

if __name__ == "__main__":    
    main()