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
