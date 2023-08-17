import os
import re
import requests
import yaml

CVE_API_URL = "https://cve.circl.lu/api/cve"

def fetch_cve_info(cve_id):
    response = requests.get(f"{CVE_API_URL}/{cve_id}")
    if response.status_code == 200:
        return response.json()
    return None

def main():
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

    for root, _, files in os.walk("."):
        for filename in files:
            if filename != "blank.yaml" and filename.endswith(".yaml"):
                yaml_path = os.path.join(root, filename)
                with open(yaml_path, "r") as f:
                    data = yaml.safe_load(f)

                if "metadata" not in data:
                    data["metadata"] = {}

                if "cpe" not in data["metadata"]:
                    with open(yaml_path, "r") as f:
                        yaml_content = f.read()
                        cve_ids = set(cve_pattern.findall(yaml_content))

                    for cve_id in cve_ids:
                        cve_info = fetch_cve_info(cve_id)
                        if cve_info:
                            metadata = {
                                "cvss-metrics": cve_info.get("cvss-vector", ""),
                                "cvss-score": cve_info.get("cvss", ""),
                                "cve-id": cve_id,
                                "cwe-id": cve_info.get("cwe", ""),
                                "cpe": cve_info.get("vulnerable_configuration", []),
                            }
                            data["metadata"].update(metadata)

                    with open(yaml_path, "w") as f:
                        yaml.dump(data, f, default_flow_style=False)

if __name__ == "__main__":
    main()
