-- H2. DGA / suspicious DNS: hosts whose queries have high character entropy, are long, mostly fail (NXDOMAIN),
-- and hit cheap TLDs. Shannon entropy is computed in SQL from the character distribution of each name.
with labels as (
    select orig_h, query, rcode_name,
           regexp_replace(lower(query), '\.[a-z]+$', '') as name_no_tld,
           regexp_extract(lower(query), '\.([a-z]+)$', 1) as tld
    from dns
    where qtype_name = 'A'
),
chars as (
    select orig_h, query, rcode_name, tld, name_no_tld, unnest(string_split(name_no_tld, '')) as ch
    from labels
),
freq as (
    select orig_h, query, rcode_name, tld, name_no_tld, ch, count(*) as n
    from chars
    where ch <> '.'
    group by orig_h, query, rcode_name, tld, name_no_tld, ch
),
entropy as (
    select orig_h, query, rcode_name, tld, length(name_no_tld) as name_len,
           round(-sum((n * 1.0 / length(name_no_tld)) * log2(n * 1.0 / length(name_no_tld))), 2) as entropy
    from freq
    group by orig_h, query, rcode_name, tld, name_no_tld
)
select orig_h,
       count(*)                                                   as queries,
       round(avg(entropy), 2)                                     as avg_entropy,
       round(avg(name_len), 1)                                    as avg_len,
       round(100.0 * count(*) filter (where rcode_name = 'NXDOMAIN') / count(*), 1) as nxdomain_pct,
       count(distinct tld)                                        as tlds,
       round(100.0 * count(*) filter (where tld in ('xyz','top','club','info','tk','gq','ml')) / count(*), 1) as cheap_tld_pct,
       min(query)                                                 as example
from entropy
group by orig_h
having avg(entropy) > 3.0 or count(*) filter (where rcode_name = 'NXDOMAIN') > 5
order by avg_entropy desc, nxdomain_pct desc
limit 10;
