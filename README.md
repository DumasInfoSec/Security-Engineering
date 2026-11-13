# Generative AI Disclaimer
**GenAI (Claude, Gemini) was used in the creation of the readme files, and for organizing and fixing issues within the python scripts. GenAI was NOT used in writing the base logic and syntax of the detections or engineering scripts**

# Security Engineering
Repository of security engineering scripts (python/powershell/ruby (coming soon)/bash) and custom detection rules (KQL/ELASTIC/SIGMA/YARA), with a specific focus on modern APT tactics and techniques like LOTL, EDR evasion, C2 detection, etc.


## Layout

| Folder | What's in it |
|---|---|
| `detections/kusto/queries/` | KQL hunting and detection queries, split into `linux/` and `windows/` |
| `detections/kusto/templates/` | Reusable KQL templates |
| `detections/rules/sigma/` | Sigma rules |
| `detections/rules/yara/` | YARA rules |
| `engineering/automation/` | Automation scripts, grouped by language |
| `engineering/detection/` | Detection tooling. `lolbas_elastic_detection` loads the LOLBAS list into Elastic and alerts on LOTL commands |
| `engineering/forensics/` | Memory scanner, prefetch parser, triage snapshot |
| `engineering/threat-intel/` | Dark web RSS scraper |

Each tool folder has its own README.
