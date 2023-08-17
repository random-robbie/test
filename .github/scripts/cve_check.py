import os
import re  
import yaml
import requests
import json

base_dir = os.path.dirname(os.path.abspath(__file__))

for root, dirs, files in os.walk(base_dir):
  if '.github' in dirs:
    dirs.remove('.github')

  for file in files:
    if file.endswith('.yaml'):
      file_path = os.path.join(root, file)

      with open(file_path) as f:
        yaml_str = yaml.dump(yaml.safe_load(f)) 
      if "cve-id" not in yaml_str:
         cve_search = re.search(r'CVE-\d+-\d+', yaml_str)

         if cve_search:
            cve_id = cve_search.group()

            url = f'https://cve.circl.lu/api/cve/{cve_id}'
            response = requests.get(url)
            response_json = json.loads(response.text)
            output = ""

            try:
                CVSS_SCORE = response_json['cvss']
                output += " cvss-score: " + str(CVSS_SCORE) + "\n"
            except:
                output += " cvss-score:\n"
                pass

            try:
                cvss_vector = response_json['cvss-vector']
                output += "    cvss-metrics: " + cvss_vector + "\n"
            except:
                output += "    cvss-metrics:\n"
                pass

            try:
                cwe = response_json['cwe']
                output += "    cwe-id: " + cwe + "\n"
            except:
                output += "    cwe-id:\n"
                pass

            try:
                cve_id = response_json['id']
                output += "    cve-id: " + cve_id + ""
            except:
                pass
            f.close()
            with open(file_path) as f:
                # Read the contents of the file
                contents = f.read()
                modified_str = contents.replace("metadata:", "metadata:\n   " + output)
                print(modified_str)
