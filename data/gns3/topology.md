# ZTA Hybrid Workforce Topology — Week 3 GNS3 Lab

This is the authoritative, human-readable spec for the GNS3 hybrid-workforce
zero-trust topology. The machine-readable topology is
[`zta_hybrid_topology.gns3`](zta_hybrid_topology.gns3) in this directory.

These files are the Week 3 GNS3 lab deliverable. They are meant for **manual
import into the GNS3 GUI** (GNS3 is installed at `C:\Program Files\GNS3` but has
no CLI on `PATH` and depends on appliances/images, so it cannot be driven
headlessly from a script). The live end-to-end demo in
`src/run_gns3_demo.py` therefore uses an alternative Docker-Zeek + generated
pcap/conn.log path described at the end of this document.

---

## 1. Network segments and IP plan

| Segment | Subnet | Gateway | Purpose |
|---|---|---|---|
| Headquarters / office | `10.10.0.0/24` | `10.10.0.1` | On-prem corporate users |
| Remote / branch office (hybrid workers) | `10.20.0.0/24` | `10.20.0.1` | Remote/hybrid workforce |
| Cloud / DMZ | `172.16.0.0/24` | `172.16.0.1` | Internet-facing services (web server) |
| Internet attacker | `203.0.113.0/24` | `203.0.113.1` | Outside attacker (TEST-NET-3, documentation use only) |

`203.0.113.0/24` is RFC 5737 documentation address space; it is used here purely
as a stand-in for an external attacker source and carries no real-world routing.

---

## 2. Nodes

| ID | Label | Type | IP | Role |
|---|---|---|---|---|
| 1 | Core-Router | router | `10.10.0.1` / `10.20.0.1` / `172.16.0.1` / `203.0.113.1` | Routes between HQ, branch, DMZ, and the internet edge |
| 2 | SW-HQ | switch | — | Headquarters L2 segment (`10.10.0.0/24`) |
| 3 | HQ-Workstation | VPCS | `10.10.0.10` | Legitimate HQ user |
| 4 | SW-Branch | switch | — | Remote/branch L2 segment (`10.20.0.0/24`) |
| 5 | Branch-Hybrid-Worker | VPCS | `10.20.0.10` | Legitimate remote/hybrid worker |
| 6 | Branch-Compromised-Host | VPCS | `10.20.0.50` | **Inside attacker** (compromised branch host) |
| 7 | SW-DMZ | switch | — | Cloud/DMZ L2 segment (`172.16.0.0/24`) |
| 8 | DMZ-Web-Server | VPCS | `172.16.0.10` | Internet-facing web service (common target) |
| 9 | Internet-Attacker | VPCS | `203.0.113.10` | **Outside attacker** (internet) |
| 10 | ZTA-Policy-Enforcement-Point | VPCS/host | `0.0.0.0:5000` | Host running the Flask risk-scoring API (`src/api.py`) |
| 11 | Zeek-SPAN-Tap | switch | — | Zeek capture sensor (SPAN/mirror port) |

Node `type` values are generic placeholders (`router` / `switch` / `VPCS`). The
exact appliance images (e.g. a specific IOSv image, an Ethernet switch, a VPCS
node) depend on the images installed in the user's GNS3 install — swap them for
equivalent appliances on import.

---

## 3. ZTA policy enforcement point (where the Flask API sits)

The **ZTA-Policy-Enforcement-Point** (node 10) is the host running the Flask
risk-scoring API, `src/api.py`. It binds `0.0.0.0:5000` and exposes:

- `GET /health` — liveness probe.
- `POST /predict` — accepts a connection feature JSON, applies the pre-trained
  CNN-GRU + autoencoder pipeline (`data/cnn_gru_model.keras`, `data/scaler.pkl`,
  `data/encoders.pkl`, `data/n_features.pkl`), and returns a risk score and a
  ZTA action (`risk_score = 1 - P(Normal)`; `>0.8` BLOCK, `>0.5` CHALLENGE_MFA,
  `>0.3` MONITOR, else ALLOW).

The enforcement point is placed **inline** on the path so that east-west and
north-south traffic between the segments and the DMZ flows through it. Each
classified connection is appended to `data/audit.jsonl` (one JSON object per
line: `timestamp`, `connection_id`, `risk_score`, `classification`, `action`,
`confidence`).

---

## 4. Zeek capture / tap placement

Zeek captures traffic via the **Zeek-SPAN-Tap** (node 11), which is a SPAN /
mirror port on **the link into the ZTA enforcement point** (link 11 in the
`.gns3` file, marked `"span_tap": true`). This is the single observation point:
every packet that reaches the enforcement point is mirrored to Zeek, so the
same traffic the API scores is the traffic Zeek parses.

Zeek emits `conn.log` files in the Bro/Zeek TSV format whose `#fields` header
matches `data/logs/conn.log` exactly. Those conn.logs are consumed by
`src/zeek_capture.parse_conn_log` / `parse_conn_log_row`, which map each conn.log
row to the 40-feature vector the model expects (duration, protocol_type, service
(`-` -> `other`), flag (conn_state), src_bytes (orig_bytes), dst_bytes
(resp_bytes), count (orig_pkts), srv_count (resp_pkts), and the remaining 32
features from `FEATURE_DEFAULTS`).

The Zeek Docker image is `zeek/zeek:latest`; see section 6 for why the live demo
falls back to generated pcaps/conn.logs when that image or the Docker daemon is
unavailable.

---

## 5. Attack sources and traffic-class origins

The five traffic classes (`Normal`, `DoS`, `Probe`, `R2L`, `U2R`) map to the
nodes above as follows:

| Class | Origin (node) | Source type | Typical target |
|---|---|---|---|
| Normal | HQ-Workstation (`10.10.0.10`) and Branch-Hybrid-Worker (`10.20.0.10`) | legitimate user | DMZ-Web-Server (`172.16.0.10`) / internal services |
| DoS | Internet-Attacker (`203.0.113.10`) and Branch-Compromised-Host (`10.20.0.50`) | outside + inside | DMZ-Web-Server (`172.16.0.10`) flood |
| Probe | Internet-Attacker (`203.0.113.10`) and Branch-Compromised-Host (`10.20.0.50`) | outside + inside | scan of HQ/branch/DMZ subnets |
| R2L | Branch-Compromised-Host (`10.20.0.50`) and Internet-Attacker (`203.0.113.10`) | inside + outside | HQ-Workstation (`10.10.0.10`) remote-to-local / password guessing |
| U2R | Branch-Compromised-Host (`10.20.0.50`) | inside | DMZ-Web-Server (`172.16.0.10`) privilege escalation |

Inside vs outside attack sources:

- **Inside attacker**: `Branch-Compromised-Host` (`10.20.0.50`) — a legitimate
  branch address that has been compromised. It originates DoS, Probe, R2L, and
  U2R traffic from inside the branch segment.
- **Outside attacker**: `Internet-Attacker` (`203.0.113.10`) — an internet host
  on the `203.0.113.0/24` edge. It originates DoS, Probe, and R2L traffic from
  outside the corporate network.

The Scapy generator (`src/generate_attack_traffic.py`, FEAT-002) crafts pcaps
that emulate these source/destination pairs so the captured conn.logs reflect
this topology's IP plan.

---

## 6. Alternative demo path (Docker-Zeek + generated pcap/conn.log)

GNS3 cannot be driven headlessly from a script (no CLI on `PATH`; needs the GUI
and user-supplied appliances/images). The live end-to-end demo therefore uses an
alternative, reproducible path that does not require GNS3 to be running:

1. `python src/generate_attack_traffic.py` — Scapy writes pcaps for all five
   classes to `data/gns3/pcaps/*.pcap`.
2. Where the Docker daemon is up and `zeek/zeek:latest` is available, the demo
   runs Zeek over Docker on those pcaps to produce
   `data/gns3/conn_logs/*_conn.log`. If Zeek/Docker is unavailable, the demo
   falls back to **pre-generated conn.logs** (same Bro/Zeek TSV `#fields` format)
   so the pipeline still runs end-to-end. It records which path was used in
   `data/results/gns3_demo_results.json` — it never fabricates Zeek output.
3. `python src/run_gns3_demo.py` parses each conn.log with
   `src/zeek_capture.parse_conn_log`, maps rows to the 40-feature vector, calls
   the Flask `POST /predict`, records the risk score and ZTA action, appends to
   `data/audit.jsonl`, and writes `data/results/gns3_demo_results.json`
   (valid JSON covering all five classes) plus a summary table.

This topology file is referenced by **path** in the demo's results JSON
(`topology` field) but the demo does not need these files to run.

---

## 7. Importing `zta_hybrid_topology.gns3` into GNS3

These steps assume the GNS3 GUI is installed (default path
`C:\Program Files\GNS3`).

1. Open the GNS3 GUI.
2. `File` -> `New project`. Give it a name (e.g. `zta-hybrid-workforce`) and a
   location, then click `OK`.
3. `File` -> `Import legacy project` (or `Open project` if your GNS3 version
   reads `.gns3` directly) and select
   `data/gns3/zta_hybrid_topology.gns3`.
   - On newer GNS3 versions you can also use `File` -> `Open project` and browse
     to the `.gns3` file directly.
4. Because node `type` values are generic placeholders, GNS3 will warn that it
   cannot find matching appliances. For each node, replace the placeholder with
   an equivalent installed appliance:
   - `router` -> an installed router image (e.g. IOSv).
   - `switch` -> an Ethernet switch node, or an installed L3 switch image.
   - `VPCS` -> the built-in VPCS appliance (built into GNS3).
5. Re-map each node's interfaces to the new appliance's interfaces to preserve
   the connectivity in the `links` section (HQ, branch, DMZ, internet edge, and
   the Zeek SPAN tap into the ZTA enforcement point).
6. Configure node IPs per the IP plan in section 1 and the per-node properties
   in section 2 (or rely on the `properties` block in the `.gns3` file).
7. Start the nodes, then start the Flask enforcement point out-of-band:
   `python src/api.py` (binds `0.0.0.0:5000`) on the host that acts as the
   ZTA-Policy-Enforcement-Point.
8. Configure the SPAN/mirror port on the link into the enforcement point so
   Zeek receives a copy of the traffic (the Zeek-SPAN-Tap node). Point Zeek's
   log output at `data/gns3/conn_logs/` so `src/zeek_capture.parse_conn_log` can
   consume the resulting `conn.log` files.

> Note: manual GNS3 import + appliance substitution is a lab step; the
> reproducible automated demo does not require GNS3 and uses the alternative
> path in section 6 instead.
