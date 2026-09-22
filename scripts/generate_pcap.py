"""Generate data/traffic.pcap: 8 hours of a small office's traffic with three planted threats.

Background (benign): ~60 workstations browsing HTTPS to popular sites at human-like intervals, DNS lookups
for real-looking domains, a few long-lived legitimate connections (VPN, video call), NTP.

Planted:
  1. C2 beacon: ws 10.10.2.117 → 45.133.1.9:443 every 60 s ± 5 % jitter, tiny fixed-size payloads, 8 hours.
     (Rules see "HTTPS to an IP" and nothing else; the *regularity* is the signal.)
  2. DGA: ws 10.10.3.42 resolves 40 high-entropy .xyz/.top domains over 20 minutes, most NXDOMAIN.
  3. Exfiltration: ws 10.10.1.77 opens one connection to 185.220.101.9:443 and sends 38 MB out over 40 minutes,
     with almost nothing coming back (asymmetric bytes).

data/ground_truth.json records what was planted so detections can be scored.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, RawPcapWriter

random.seed(11)
START = 1_756_886_400  # 2025-09-03 08:00:00 UTC
HOURS = 8
END = START + HOURS * 3600
WS = [f"10.10.{random.randint(1, 4)}.{random.randint(10, 250)}" for _ in range(60)]
DNS_SERVER = "10.10.0.53"
GATEWAY_MAC, WS_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
SITES = {
    "www.google.com": "142.250.72.4", "www.microsoft.com": "20.70.246.20", "outlook.office365.com": "52.96.166.2",
    "www.github.com": "140.82.112.4", "cdn.jsdelivr.net": "104.16.86.20", "www.cbc.ca": "23.35.145.75",
    "teams.microsoft.com": "52.113.194.132", "www.youtube.com": "142.250.72.14", "slack.com": "3.98.16.20",
    "www.wikipedia.org": "208.80.154.224", "api.openai.com": "104.18.32.47", "www.amazon.ca": "54.239.19.116",
}
PACKETS: list[tuple[float, bytes]] = []  # buffered so the file can be written in timestamp order (Zeek needs monotonic time)
flows = []  # (ts, src, dst, dport, proto, bytes_out, bytes_in, duration, label)


def tcp_flow(ts: float, src: str, dst: str, dport: int, out_bytes: int, in_bytes: int, duration: float, label: str = "benign"):
    """Write a compressed TCP conversation: handshake, N data packets each way, FIN. Zeek reconstructs conn.log from it."""
    sport = random.randint(40000, 60000)
    seq, ack = random.randint(1, 2**31), random.randint(1, 2**31)
    pk = lambda t, p: PACKETS.append((t, bytes(p)))  # noqa: E731
    pk(ts, Ether(src=WS_MAC, dst=GATEWAY_MAC) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq))
    pk(ts + 0.02, Ether(src=GATEWAY_MAC, dst=WS_MAC) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq + 1))
    pk(ts + 0.04, Ether(src=WS_MAC, dst=GATEWAY_MAC) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1))
    n_out, n_in = max(1, out_bytes // 1400), max(1, in_bytes // 1400) if in_bytes else 0
    total = max(n_out + n_in, 1)
    t = ts + 0.05
    s, a = seq + 1, ack + 1
    for i in range(n_out):
        size = min(1400, out_bytes - i * 1400) if i < n_out - 1 else max(1, out_bytes - 1400 * (n_out - 1))
        pk(t, Ether(src=WS_MAC, dst=GATEWAY_MAC) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(b"\x17\x03\x03" + bytes(size)))
        s += size
        t += duration / total
    for i in range(n_in):
        size = min(1400, in_bytes - i * 1400) if i < n_in - 1 else max(1, in_bytes - 1400 * (n_in - 1))
        pk(t, Ether(src=GATEWAY_MAC, dst=WS_MAC) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(b"\x17\x03\x03" + bytes(size)))
        a += size
        t += duration / total
    pk(t, Ether(src=WS_MAC, dst=GATEWAY_MAC) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=s, ack=a))
    pk(t + 0.02, Ether(src=GATEWAY_MAC, dst=WS_MAC) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=a, ack=s + 1))
    flows.append((ts, src, dst, dport, "tcp", out_bytes, in_bytes, duration, label))


def _stamp(p, t):
    PACKETS.append((t, bytes(p)))
    return p


class _Sink:
    def write(self, _):  # every write goes through _stamp/pk into PACKETS
        pass


writer = _Sink()


def dns_query(ts: float, src: str, name: str, answer: str | None, label: str = "benign"):
    sport, txid = random.randint(40000, 60000), random.randint(0, 65535)
    writer.write(_stamp(Ether(src=WS_MAC, dst=GATEWAY_MAC) / IP(src=src, dst=DNS_SERVER) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name)), ts))
    if answer:
        resp = DNS(id=txid, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=300, rdata=answer))
    else:
        resp = DNS(id=txid, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name))
    writer.write(_stamp(Ether(src=GATEWAY_MAC, dst=WS_MAC) / IP(src=DNS_SERVER, dst=src) / UDP(sport=53, dport=sport) / resp, ts + 0.01))
    flows.append((ts, src, DNS_SERVER, 53, "dns", 0, 0, 0, label))


def dga_name(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()
    return h[: random.randint(12, 20)] + random.choice([".xyz", ".top", ".club", ".info"])


# ---------------- benign background ----------------
events = []
for ws in WS:
    t = START + random.uniform(0, 600)
    while t < END:
        site = random.choice(list(SITES))
        events.append((t, "browse", ws, site))
        t += random.expovariate(1 / 240)  # a request every ~4 min on average, very irregular
# a few legit long connections: VPN and a video call
events.append((START + 300, "long", WS[0], "vpn"))
events.append((START + 3600 * 3, "long", WS[5], "call"))
for ws in WS:
    events.append((START + random.uniform(0, 3600), "ntp", ws, "ntp"))

# ---------------- planted ----------------
BEACON_WS, BEACON_C2 = "10.10.2.117", "45.133.1.9"
t = START + 1800
while t < END:
    events.append((t, "beacon", BEACON_WS, BEACON_C2))
    t += 60 * random.uniform(0.95, 1.05)
DGA_WS = "10.10.3.42"
t = START + 4 * 3600
for i in range(40):
    events.append((t, "dga", DGA_WS, dga_name(f"seed-{i}")))
    t += random.uniform(15, 45)
EXFIL_WS, EXFIL_DST = "10.10.1.77", "185.220.101.9"
events.append((START + 6 * 3600 + 900, "exfil", EXFIL_WS, EXFIL_DST))

events.sort()
for ts, kind, src, target in events:
    if kind == "browse":
        dns_query(ts, src, target, SITES[target])
        tcp_flow(ts + 0.05, src, SITES[target], 443, random.randint(800, 6000), random.randint(5_000, 120_000), random.uniform(0.3, 12))
    elif kind == "ntp":
        writer.write(_stamp(Ether(src=WS_MAC, dst=GATEWAY_MAC) / IP(src=src, dst="162.159.200.1") / UDP(sport=123, dport=123) / Raw(bytes(48)), ts))
    elif kind == "long":
        if target == "vpn":
            tcp_flow(ts, src, "198.51.100.77", 443, 4_000_000, 6_000_000, 7 * 3600, "benign-long")
        else:
            tcp_flow(ts, src, "52.113.194.132", 443, 9_000_000, 11_000_000, 3600, "benign-long")
    elif kind == "beacon":
        tcp_flow(ts, src, target, 443, random.choice([612, 612, 612, 640]), random.choice([1120, 1120, 1152]), 0.4, "c2-beacon")
    elif kind == "dga":
        dns_query(ts, src, target, "45.133.1.9" if random.random() < 0.1 else None, "dga")
    elif kind == "exfil":
        tcp_flow(ts, src, target, 443, 38_000_000, 120_000, 2400, "exfil")
PACKETS.sort(key=lambda x: x[0])
with RawPcapWriter("data/traffic.pcap", linktype=1, append=False, sync=False) as out:  # linktype 1 = Ethernet
    out._write_header(None)
    for t, raw in PACKETS:
        out._write_packet(raw, sec=int(t), usec=int((t - int(t)) * 1_000_000), linktype=1)

truth = {
    "c2_beacon": {"src": BEACON_WS, "dst": BEACON_C2, "dport": 443, "interval_s": 60, "flows": sum(1 for f in flows if f[8] == "c2-beacon")},
    "dga": {"src": DGA_WS, "queries": sum(1 for f in flows if f[8] == "dga")},
    "exfil": {"src": EXFIL_WS, "dst": EXFIL_DST, "bytes_out": 38_000_000},
    "benign_long_connections": [{"src": WS[0], "dst": "198.51.100.77"}, {"src": WS[5], "dst": "52.113.194.132"}],
}
Path("data/ground_truth.json").write_text(json.dumps(truth, indent=2))
print(f"wrote data/traffic.pcap: {len(PACKETS):,} packets, {len(flows):,} flows ({sum(1 for f in flows if f[8] != 'benign')} planted), {Path('data/traffic.pcap').stat().st_size / 1e6:.0f} MB")
