# Scorecard (against data/ground_truth.json)

| planted threat | hunt | rank in results | verdict |
|---|---|---:|---|
| C2 beacon 10.10.2.117 → 45.133.1.9 every 60 s (451 connections) | H1 beaconing | 1 | found |
| DGA on 10.10.3.42 (40 queries) | H2 DNS entropy | 1 | found |
| Exfil 10.10.1.77 → 185.220.101.9 (38 MB out) | H3 asymmetry | 1 | found |
| Benign long connections (VPN, video call) | H4 duration | 2 of 2 listed | listed but distinguishable by symmetry — H4 is a triage list, not a verdict |

Corpus: 14,650 connections, 7,088 DNS queries, 59 internal hosts, 8 hours.
