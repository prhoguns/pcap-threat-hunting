# H5. Rare external destinations: IPs that only one internal host talks to. Everyone talks to Microsoft; one host talking

```sql
-- H5. Rare external destinations: IPs that only one internal host talks to. Everyone talks to Microsoft; one host talking
-- to an IP nobody else does is worth a look. Joined with whether the IP was ever resolved by DNS (direct-to-IP is odd for HTTPS).
with dest as (
    select resp_h, count(distinct orig_h) as hosts, count(*) as connections, min(orig_h) as the_host, sum(orig_bytes) as bytes_out
    from conn
    where proto = 'tcp' and not resp_h like '10.%'
    group by 1
),
resolved as (
    select distinct unnest(answers) as ip from dns
)
select d.resp_h, d.hosts, d.connections, d.the_host, round(d.bytes_out / 1e6, 2) as mb_out,
       case when r.ip is null then 'never in a DNS answer' else 'resolved via DNS' end as dns_context
from dest d
left join resolved r on r.ip = d.resp_h
where d.hosts = 1
order by d.connections desc, d.bytes_out desc
limit 10;
```

| resp_h | hosts | connections | the_host | mb_out | dns_context |
|:---|---:|---:|:---|---:|:---|
| 45.133.1.9 | 1 | 451 | 10.10.2.117 | 0.28 | resolved via DNS |
| 185.220.101.9 | 1 | 1 | 10.10.1.77 | 38 | never in a DNS answer |
| 198.51.100.77 | 1 | 1 | 10.10.4.231 | 4 | never in a DNS answer |
