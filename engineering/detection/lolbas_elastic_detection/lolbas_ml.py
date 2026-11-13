#!/usr/bin/env python3
"""Create or update one ML anomaly detection job: LOLBAS binaries that are rare for a host.

Run it after lolbas_sync.py. It is safe to run again and again:
  - first run:        creates the job and its datafeed, opens the job, starts the datafeed
  - LOLBAS list same: does nothing
  - LOLBAS list changed: updates the datafeed query (stop, update, start again).
                         A datafeed that someone stopped on purpose stays stopped.

Usage:
  python3 lolbas_ml.py            # create or update
  python3 lolbas_ml.py --status   # show the job and datafeed state, change nothing

Python 3.6+, standard library only.
"""
import argparse
import sys
import time

from lolbas_common import BINARIES_INDEX, es, load_config, setting

JOB_ID = "lolbas_rare_binary_by_host"
DATAFEED_ID = "datafeed-" + JOB_ID


def lolbas_names():
    _, result = es("POST", "/%s/_search" % BINARIES_INDEX,
                   {"size": 2000, "_source": ["lolbas_name"], "sort": ["lolbas_name"]}, ok=(200, 404))
    names = [hit["_source"]["lolbas_name"] for hit in result.get("hits", {}).get("hits", [])]
    if not names:
        sys.exit("ERROR: %s is empty or missing. Run lolbas_sync.py first." % BINARIES_INDEX)
    return names


def datafeed_query(names):
    """process start events for lolbas binaries, hot tier only"""
    return {"bool": {
        "filter": [
            {"term": {"event.category": "process"}},
            {"term": {"event.type": "start"}},
            # names show up in mixed case (MSBuild.exe) so ignore case
            {"bool": {"minimum_should_match": 1, "should": [
                {"term": {"process.name": {"value": name, "case_insensitive": True}}} for name in names
            ]}},
        ],
        # hot tier only. a lagging datafeed chewing through warm data
        # pegged our warm nodes once, not doing that again
        "must_not": [{"terms": {"_tier": ["data_warm", "data_cold", "data_frozen"]}}],
    }}


def names_in_query(query):
    """pull the binary names back out of an existing datafeed query"""
    names = []
    for clause in query.get("bool", {}).get("filter", []):
        for should in clause.get("bool", {}).get("should", []):
            value = should.get("term", {}).get("process.name", {}).get("value")
            if value:
                names.append(value.lower())
    return sorted(names)


def datafeed_state():
    _, stats = es("GET", "/_ml/datafeeds/%s/_stats" % DATAFEED_ID)
    return stats["datafeeds"][0]["state"]


def create(names):
    es("PUT", "/_ml/anomaly_detectors/" + JOB_ID, {
        "description": "LOLBAS binaries that are rare for a host",
        "groups": ["lolbas"],
        "analysis_config": {
            "bucket_span": "15m",
            "detectors": [{
                "detector_description": "LOLBAS binary rare for this host",
                "function": "rare",
                "by_field_name": "process.name",
                "partition_field_name": "host.name",
            }],
            "influencers": ["host.name", "user.name", "process.name", "process.parent.name"],
        },
        "analysis_limits": {"model_memory_limit": setting("ML_MEMORY_LIMIT", "512mb")},
        "data_description": {"time_field": "@timestamp"},
    })
    es("PUT", "/_ml/datafeeds/" + DATAFEED_ID, {
        "job_id": JOB_ID,
        "indices": setting("INDEX_PATTERNS").split(","),
        "indices_options": {"ignore_unavailable": True, "allow_no_indices": True},
        "query": datafeed_query(names),
        "query_delay": "120s",
        "scroll_size": 1000,
    })
    es("POST", "/_ml/anomaly_detectors/%s/_open" % JOB_ID)
    start = setting("ML_START", "now-1d")
    es("POST", "/_ml/datafeeds/%s/_start" % DATAFEED_ID, {"start": start})
    print("created job %s, datafeed started from %s (%d binaries)" % (JOB_ID, start, len(names)))


def update(names):
    was_started = datafeed_state() == "started"
    if was_started:
        es("POST", "/_ml/datafeeds/%s/_stop" % DATAFEED_ID)
    es("POST", "/_ml/datafeeds/%s/_update" % DATAFEED_ID, {"query": datafeed_query(names)})
    if was_started:
        # no start time = pick up where it left off
        es("POST", "/_ml/datafeeds/%s/_start" % DATAFEED_ID, {})
        print("updated datafeed query (%d binaries) and restarted it" % len(names))
    else:
        print("updated datafeed query (%d binaries). The datafeed was stopped, so it stays stopped." % len(names))


def show_status():
    _, job = es("GET", "/_ml/anomaly_detectors/%s/_stats" % JOB_ID, ok=(200, 404))
    if not job.get("jobs"):
        print("job %s does not exist yet" % JOB_ID)
        return
    _, feed = es("GET", "/_ml/datafeeds/%s/_stats" % DATAFEED_ID)
    job, feed = job["jobs"][0], feed["datafeeds"][0]
    print("job state:      ", job.get("state"))
    print("memory status:  ", job.get("model_size_stats", {}).get("memory_status"))
    print("records read:   ", job.get("data_counts", {}).get("processed_record_count"))
    print("datafeed state: ", feed.get("state"))
    end_ms = feed.get("running_state", {}).get("search_interval", {}).get("end_ms")
    if end_ms:
        print("minutes behind: ", round((time.time() * 1000 - end_ms) / 60000, 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--status", action="store_true", help="show state only, change nothing")
    args = parser.parse_args()
    load_config()

    if args.status:
        show_status()
        return

    names = lolbas_names()
    status, existing = es("GET", "/_ml/datafeeds/" + DATAFEED_ID, ok=(200, 404))
    if status == 404 or not existing.get("datafeeds"):
        create(names)
    elif names_in_query(existing["datafeeds"][0].get("query", {})) != sorted(names):
        update(names)
    else:
        print("datafeed already matches the LOLBAS list (%d binaries), nothing to do" % len(names))


if __name__ == "__main__":
    main()
