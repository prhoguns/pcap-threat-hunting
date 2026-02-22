# H3. Exfiltration: single connections that send far more than they receive, to external hosts, ranked by bytes out.

```sql
-- H3. Exfiltration: single connections that send far more than they receive, to external hosts, ranked by bytes out.
-- Normal browsing is heavily download-biased (ratio << 1). Uploads to unknown external IPs with ratio >> 1 are the signal.
select orig_h, resp_h, resp_p, ts,
       round(duration / 60.0, 1)                            as minutes,
       round(orig_bytes / 1e6, 1)                           as mb_out,
       round(resp_bytes / 1e6, 2)                           as mb_in,
       round(orig_bytes * 1.0 / greatest(resp_bytes, 1), 1) as out_in_ratio
from conn
where proto = 'tcp' and not resp_h like '10.%' and orig_bytes > 5e6
order by out_in_ratio desc, orig_bytes desc
limit 10;
```

| orig_h | resp_h | resp_p | ts | minutes | mb_out | mb_in | out_in_ratio |
|:---|:---|---:|:---|---:|---:|---:|---:|
| 10.10.1.77 | 185.220.101.9 | 443 | 14:15:00 | 40 | 38 | 0.12 | 316.7 |
| 10.10.4.87 | 52.113.194.132 | 443 | 11:00:00 | 60 | 9 | 11 | 0.8 |
