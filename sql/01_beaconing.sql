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
