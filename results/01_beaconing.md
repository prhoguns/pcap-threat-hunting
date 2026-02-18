# H1. Beaconing: for every (src, dst, port) with enough connections, how regular are the intervals between them?

```sql
-- H1. Beaconing: for every (src, dst, port) with enough connections, how regular are the intervals between them?
-- Real users are bursty (coefficient of variation ~1); malware on a timer is regular (CV near 0), even with jitter.
-- Score = regularity (low interval CV) x consistency of size (low bytes CV) x count. Rules never see this; it needs the timeline.
with ordered as (
    select orig_h, resp_h, resp_p, ts, orig_bytes,
           epoch(ts) - lag(epoch(ts)) over (partition by orig_h, resp_h, resp_p order by ts) as gap
    from conn
    where proto = 'tcp' and not resp_h like '10.%'
),
stats as (
    select orig_h, resp_h, resp_p,
           count(*)                                   as connections,
           round(avg(gap), 1)                         as mean_gap_s,
           round(stddev_samp(gap) / nullif(avg(gap), 0), 3) as gap_cv,
           round(stddev_samp(orig_bytes) / nullif(avg(orig_bytes), 0), 3) as bytes_cv,
           round(avg(orig_bytes))                     as mean_bytes_out,
           round(epoch(max(ts)) - epoch(min(ts)))     as span_s
    from ordered
    group by 1, 2, 3
    having count(*) >= 20
)
select *,
       round((1 - least(gap_cv, 1)) * (1 - least(bytes_cv, 1)) * log(connections), 3) as beacon_score
from stats
order by beacon_score desc
limit 15;
```

| orig_h | resp_h | resp_p | connections | mean_gap_s | gap_cv | bytes_cv | mean_bytes_out | span_s | beacon_score |
|:---|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| 10.10.2.117 | 45.133.1.9 | 443 | 451 | 60 | 0.029 | 0.019 | 620 | 26,984.0 | 2.528 |
| 10.10.4.117 | 140.82.112.4 | 443 | 21 | 1,324.7 | 0.665 | 0.419 | 3,379.0 | 26,493.0 | 0.257 |
| 10.10.4.125 | 208.80.154.224 | 443 | 20 | 1,398.1 | 0.726 | 0.41 | 3,936.0 | 26,564.0 | 0.21 |
| 10.10.1.154 | 23.35.145.75 | 443 | 28 | 1,027.9 | 0.776 | 0.393 | 3,720.0 | 27,753.0 | 0.197 |
| 10.10.4.125 | 54.239.19.116 | 443 | 20 | 1,203.8 | 0.782 | 0.5 | 3,353.0 | 22,872.0 | 0.142 |
| 10.10.3.137 | 208.80.154.224 | 443 | 20 | 1,365.7 | 0.824 | 0.431 | 3,651.0 | 25,948.0 | 0.13 |
| 10.10.4.117 | 104.16.86.20 | 443 | 32 | 848.5 | 0.908 | 0.382 | 3,548.0 | 26,304.0 | 0.086 |
| 10.10.4.117 | 52.113.194.132 | 443 | 23 | 1,041.8 | 0.856 | 0.581 | 2,855.0 | 22,919.0 | 0.082 |
| 10.10.4.125 | 52.96.166.2 | 443 | 20 | 1,401.9 | 0.892 | 0.466 | 3,303.0 | 26,637.0 | 0.075 |
| 10.10.4.117 | 23.35.145.75 | 443 | 24 | 1,212.0 | 0.955 | 0.498 | 3,711.0 | 27,877.0 | 0.031 |
| 10.10.4.117 | 3.98.16.20 | 443 | 20 | 1,280.2 | 0.963 | 0.484 | 3,207.0 | 24,324.0 | 0.025 |
| 10.10.4.125 | 3.98.16.20 | 443 | 26 | 1,097.6 | 0.986 | 0.489 | 3,191.0 | 27,441.0 | 0.01 |
| 10.10.1.154 | 142.250.72.14 | 443 | 21 | 969.5 | 0.998 | 0.422 | 3,571.0 | 19,390.0 | 0.002 |
| 10.10.1.89 | 140.82.112.4 | 443 | 20 | 1,216.7 | 1.066 | 0.399 | 3,568.0 | 23,117.0 | 0 |
| 10.10.4.125 | 142.250.72.4 | 443 | 22 | 1,326.0 | 1.1 | 0.436 | 3,566.0 | 27,845.0 | 0 |
