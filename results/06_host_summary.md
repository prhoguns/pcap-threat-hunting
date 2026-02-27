# H6. Per-host summary for the analyst: connections, distinct external destinations, bytes, NXDOMAIN count, beacon flag.

```sql
-- H6. Per-host summary for the analyst: connections, distinct external destinations, bytes, NXDOMAIN count, beacon flag.
with per_host as (
    select orig_h,
           count(*) as connections,
           count(distinct resp_h) filter (where not resp_h like '10.%') as ext_destinations,
           round(sum(orig_bytes) / 1e6, 1) as mb_out,
           round(sum(resp_bytes) / 1e6, 1) as mb_in
    from conn where proto = 'tcp' group by 1
),
nx as (select orig_h, count(*) as nxdomains from dns where rcode_name = 'NXDOMAIN' group by 1)
select p.*, coalesce(n.nxdomains, 0) as nxdomains,
       round(p.mb_out / greatest(p.mb_in, 0.01), 2) as out_in_ratio
from per_host p left join nx n using (orig_h)
order by out_in_ratio desc
limit 12;
```

| orig_h | connections | ext_destinations | mb_out | mb_in | nxdomains | out_in_ratio |
|:---|---:|---:|---:|---:|---:|---:|
| 10.10.1.77 | 1 | 1 | 38 | 0.1 | 0 | 380 |
| 10.10.4.87 | 122 | 12 | 9.4 | 19 | 0 | 0.49 |
| 10.10.4.231 | 133 | 13 | 4.4 | 14.8 | 0 | 0.3 |
| 10.10.2.117 | 572 | 13 | 0.7 | 7.9 | 0 | 0.09 |
| 10.10.1.130 | 100 | 12 | 0.4 | 5.9 | 0 | 0.07 |
| 10.10.4.191 | 100 | 12 | 0.4 | 6 | 0 | 0.07 |
| 10.10.3.13 | 112 | 12 | 0.4 | 6.1 | 0 | 0.07 |
| 10.10.3.231 | 106 | 12 | 0.4 | 6 | 0 | 0.07 |
| 10.10.2.110 | 104 | 12 | 0.4 | 5.9 | 0 | 0.07 |
| 10.10.2.142 | 107 | 12 | 0.4 | 6.4 | 0 | 0.06 |
| 10.10.3.108 | 111 | 12 | 0.4 | 6.9 | 0 | 0.06 |
| 10.10.2.57 | 120 | 12 | 0.4 | 6.8 | 0 | 0.06 |
