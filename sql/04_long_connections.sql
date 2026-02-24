-- H4. Long-lived connections: the classic "is that a VPN or a reverse shell" list. Duration alone is not a verdict:
-- the two benign long connections here are a VPN and a video call. Bytes and symmetry tell them apart.
select orig_h, resp_h, resp_p,
       round(duration / 3600.0, 2)                          as hours,
       round(orig_bytes / 1e6, 1)                           as mb_out,
       round(resp_bytes / 1e6, 1)                           as mb_in,
       round(orig_bytes * 1.0 / greatest(resp_bytes, 1), 2) as out_in_ratio
from conn
where proto = 'tcp' and duration > 1800
order by duration desc
limit 10;
