"""Run every hunt in sql/, write results/<name>.md, and score against data/ground_truth.json."""
from __future__ import annotations

import json
import math
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

DB = "data/hunt.duckdb"


def fmt(v, col=""):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return ""
    if isinstance(v, (int, np.integer)):
        return f"{int(v):,}" if not any(k in col for k in ("_p", "port")) else str(int(v))
    if isinstance(v, (float, np.floating)):
        return f"{v:,.3f}".rstrip("0").rstrip(".") if abs(v) < 1000 else f"{v:,.1f}"
    if isinstance(v, pd.Timestamp):
        return v.strftime("%H:%M:%S")
    return str(v)


def md(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    head = "| " + " | ".join(cols) + " |"
    sep = "|" + "|".join("---:" if pd.api.types.is_numeric_dtype(df[c]) else ":---" for c in cols) + "|"
    rows = ["| " + " | ".join(fmt(v, c) for v, c in zip(r, cols, strict=True)) + " |" for r in df.itertuples(index=False, name=None)]
    return "\n".join([head, sep, *rows])


def main() -> None:
    con = duckdb.connect(DB, read_only=True)
    truth = json.loads(Path("data/ground_truth.json").read_text())
    Path("results").mkdir(exist_ok=True)
    out = {}
    for path in sorted(Path("sql").glob("*.sql")):
        sql = path.read_text()
        df = con.execute(sql).df()
        out[path.stem] = df
        title = next(line.lstrip("- ").strip() for line in sql.splitlines() if line.startswith("-- H"))
        Path(f"results/{path.stem}.md").write_text(f"# {title}\n\n```sql\n{sql.strip()}\n```\n\n{md(df)}\n")
        print(f"{path.stem}: {len(df)} rows")

    # ---- scoring against ground truth ----
    b = out["01_beaconing"]
    beacon_rank = int(b.index[(b.orig_h == truth["c2_beacon"]["src"]) & (b.resp_h == truth["c2_beacon"]["dst"])][0]) + 1 if ((b.orig_h == truth["c2_beacon"]["src"]) & (b.resp_h == truth["c2_beacon"]["dst"])).any() else None
    d = out["02_dga_dns"]
    dga_rank = int(d.index[d.orig_h == truth["dga"]["src"]][0]) + 1 if (d.orig_h == truth["dga"]["src"]).any() else None
    e = out["03_exfiltration"]
    exfil_rank = int(e.index[(e.orig_h == truth["exfil"]["src"]) & (e.resp_h == truth["exfil"]["dst"])][0]) + 1 if ((e.orig_h == truth["exfil"]["src"]) & (e.resp_h == truth["exfil"]["dst"])).any() else None
    long_ = out["04_long_connections"]
    benign_long = {(x["src"], x["dst"]) for x in truth["benign_long_connections"]}
    long_flagged_benign = sum((r.orig_h, r.resp_h) in benign_long for r in long_.itertuples())
    score = [
        "# Scorecard (against data/ground_truth.json)", "",
        "| planted threat | hunt | rank in results | verdict |", "|---|---|---:|---|",
        f"| C2 beacon {truth['c2_beacon']['src']} → {truth['c2_beacon']['dst']} every {truth['c2_beacon']['interval_s']} s ({truth['c2_beacon']['flows']} connections) | H1 beaconing | {beacon_rank} | {'found' if beacon_rank == 1 else 'check'} |",
        f"| DGA on {truth['dga']['src']} ({truth['dga']['queries']} queries) | H2 DNS entropy | {dga_rank} | {'found' if dga_rank == 1 else 'check'} |",
        f"| Exfil {truth['exfil']['src']} → {truth['exfil']['dst']} ({truth['exfil']['bytes_out'] / 1e6:.0f} MB out) | H3 asymmetry | {exfil_rank} | {'found' if exfil_rank == 1 else 'check'} |",
        f"| Benign long connections (VPN, video call) | H4 duration | {long_flagged_benign} of 2 listed | listed but distinguishable by symmetry — H4 is a triage list, not a verdict |",
        "",
        f"Corpus: {con.execute('select count(*) from conn').fetchone()[0]:,} connections, {con.execute('select count(*) from dns').fetchone()[0]:,} DNS queries, "
        f"{con.execute('select count(distinct orig_h) from conn').fetchone()[0]} internal hosts, 8 hours.",
    ]
    Path("results/SCORECARD.md").write_text("\n".join(score) + "\n")
    print("\n".join(score))


if __name__ == "__main__":
    main()
