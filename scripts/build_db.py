"""Load Zeek JSON logs into data/hunt.duckdb with clean column names (Zeek's id.orig_h → orig_h)."""
import duckdb

DB = "data/hunt.duckdb"
con = duckdb.connect(DB)
con.execute("drop table if exists conn")
con.execute(
    """
    create table conn as
    select to_timestamp(ts) as ts, uid, "id.orig_h" as orig_h, "id.orig_p" as orig_p, "id.resp_h" as resp_h, "id.resp_p" as resp_p,
           proto, service, coalesce(duration, 0) as duration, coalesce(orig_bytes, 0) as orig_bytes, coalesce(resp_bytes, 0) as resp_bytes,
           conn_state, coalesce(orig_pkts, 0) as orig_pkts, coalesce(resp_pkts, 0) as resp_pkts
    from read_json_auto('zeek/conn.log')
    """
)
con.execute("drop table if exists dns")
con.execute(
    """
    create table dns as
    select to_timestamp(ts) as ts, uid, "id.orig_h" as orig_h, query, qtype_name, rcode_name, coalesce(answers, []) as answers
    from read_json_auto('zeek/dns.log')
    """
)
print("conn:", con.execute("select count(*) from conn").fetchone()[0], "dns:", con.execute("select count(*) from dns").fetchone()[0])
