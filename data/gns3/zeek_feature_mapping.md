# Zeek Feature Mapping — NSL-KDD ↔ Zeek conn.log

## Purpose

This document maps every NSL-KDD feature used by the ZTA-ML framework models
to its corresponding Zeek `conn.log` field or derivation strategy.

Features fall into four categories:

| Status | Meaning |
|---|---|
| **DIRECT** | Value is read directly from a Zeek `conn.log` field with matching semantics and compatible units |
| **DERIVED** | Value is computed or approximated from one or more Zeek fields; the mapping is a proxy — semantics differ from the original NSL-KDD definition |
| **DEFAULT** | A hardcoded constant is used because Zeek `conn.log` does not expose this information at the per-connection level |
| **UNAVAILABLE** | Feature cannot be observed from Zeek `conn.log` under any reasonable approximation |

The FEATURE_COLS order below matches `src/preprocess.py` exactly (40 features;
`num_outbound_cmds` was dropped as zero-variance before this list was finalised).

---

## Feature Mapping Table

| # | Feature Name | NSL-KDD Description | Zeek Field / Derivation | Status | Notes |
|---|---|---|---|---|---|
| 1 | `duration` | Length of the connection in seconds | `duration` | DIRECT | Zeek `conn.log` reports duration in seconds; missing values rendered as `-` are defaulted to 0.0 |
| 2 | `protocol_type` | Transport-layer protocol (tcp, udp, icmp) | `proto` | DIRECT | Zeek `proto` field; lowercased in `parse_conn_log_row` |
| 3 | `service` | Network service on the destination port (http, ftp, etc.) | `service` | DIRECT | Zeek `service` field; `-` replaced with `other` |
| 4 | `flag` | Status of the connection (SF, REJ, OTH, etc.) | `conn_state` | DIRECT | Zeek `conn_state` encodes connection disposition; maps directly to NSL-KDD flag values |
| 5 | `src_bytes` | Number of data bytes from source to destination | `orig_bytes` | DIRECT | Zeek `orig_bytes` is the byte count in the originator direction |
| 6 | `dst_bytes` | Number of data bytes from destination to source | `resp_bytes` | DIRECT | Zeek `resp_bytes` is the byte count in the responder direction |
| 7 | `land` | 1 if connection is from/to same host/port; 0 otherwise | Hardcoded `0` | DEFAULT | Zeek does not flag land attacks in `conn.log`; a separate script or IDS layer would be needed |
| 8 | `wrong_fragment` | Number of wrong fragments | Hardcoded `0` | DEFAULT | Fragment counts are not exposed in Zeek `conn.log`; requires IP-layer analysis |
| 9 | `urgent` | Number of urgent packets | Hardcoded `0` | DEFAULT | TCP urgent pointer counts are not reported in `conn.log` |
| 10 | `hot` | Number of hot indicators (content-level) | Hardcoded `0` | DEFAULT | Content-level indicator — requires payload/application-layer inspection beyond `conn.log` |
| 11 | `num_failed_logins` | Number of failed login attempts | Hardcoded `0` | DEFAULT | Application-layer metric; not available in `conn.log` |
| 12 | `logged_in` | 1 if successfully logged in; 0 otherwise | Hardcoded `0` | DEFAULT | Login success state is application-layer; not in `conn.log` |
| 13 | `num_compromised` | Number of compromised conditions | Hardcoded `0` | DEFAULT | Application-layer metric from the original KDD simulation environment |
| 14 | `root_shell` | 1 if root shell is obtained; 0 otherwise | Hardcoded `0` | DEFAULT | Privilege-escalation indicator; requires OS-level or application-layer telemetry |
| 15 | `su_attempted` | 1 if su/root command attempted; 0 otherwise | Hardcoded `0` | DEFAULT | OS-level event; not observable from network flow data |
| 16 | `num_root` | Number of root accesses | Hardcoded `0` | DEFAULT | Application-layer/OS-level metric; not in `conn.log` |
| 17 | `num_file_creations` | Number of file creation operations | Hardcoded `0` | DEFAULT | File-system operation; not observable from network flow |
| 18 | `num_shells` | Number of shell prompts | Hardcoded `0` | DEFAULT | Application-layer indicator; not in `conn.log` |
| 19 | `num_access_files` | Number of operations on access control files | Hardcoded `0` | DEFAULT | File-system/OS-level metric; not observable in network flow |
| 20 | `is_host_login` | 1 if login belongs to hot list; 0 otherwise | Hardcoded `0` | DEFAULT | Application-layer; requires user authentication context |
| 21 | `is_guest_login` | 1 if login is a guest login; 0 otherwise | Hardcoded `0` | DEFAULT | Application-layer; requires user authentication context |
| 22 | `count` | Number of connections to same host in past 2 seconds | `orig_pkts` (proxy) | DERIVED | NSL-KDD `count` is a 2-second window statistic over connections; `orig_pkts` (packet count) is used as a rough proxy — semantics differ materially |
| 23 | `srv_count` | Number of connections to same service in past 2 seconds | `resp_pkts` (proxy) | DERIVED | NSL-KDD `srv_count` is a 2-second window statistic; `resp_pkts` is used as proxy — semantics differ materially |
| 24 | `serror_rate` | Fraction of connections with SYN errors (same host, 2s window) | Hardcoded `0.0` | DEFAULT | Requires a rolling window aggregation across connections; not computable per-row from a single `conn.log` entry |
| 25 | `srv_serror_rate` | Fraction of connections to same service with SYN errors | Hardcoded `0.0` | DEFAULT | Same limitation as `serror_rate`; window-level statistic |
| 26 | `rerror_rate` | Fraction of connections with REJ errors (same host, 2s window) | Hardcoded `0.0` | DEFAULT | Window-level statistic; not computable per-row |
| 27 | `srv_rerror_rate` | Fraction of connections to same service with REJ errors | Hardcoded `0.0` | DEFAULT | Window-level statistic; not computable per-row |
| 28 | `same_srv_rate` | Fraction of connections to same service (same host, 2s window) | Hardcoded `1.0` | DEFAULT | Window-level statistic; defaulted to 1.0 (optimistic/normal assumption) |
| 29 | `diff_srv_rate` | Fraction of connections to different services (same host, 2s window) | Hardcoded `0.0` | DEFAULT | Window-level statistic; defaulted to 0.0 |
| 30 | `srv_diff_host_rate` | Fraction of connections to different hosts (same service, 2s window) | Hardcoded `0.0` | DEFAULT | Window-level statistic; not computable per-row |
| 31 | `dst_host_count` | Number of connections to same destination host (100-connection window) | Hardcoded `255` | DEFAULT | Requires a 100-connection rolling window over the stream; defaulted to 255 (maximum/neutral) |
| 32 | `dst_host_srv_count` | Number of connections to same service on same host (100-connection window) | Hardcoded `255` | DEFAULT | Same limitation as `dst_host_count` |
| 33 | `dst_host_same_srv_rate` | Fraction of connections to same service on same host | Hardcoded `1.0` | DEFAULT | Window-level statistic; defaulted to 1.0 |
| 34 | `dst_host_diff_srv_rate` | Fraction of connections to different services on same host | Hardcoded `0.0` | DEFAULT | Window-level statistic; defaulted to 0.0 |
| 35 | `dst_host_same_src_port_rate` | Fraction of connections using same source port on same host | Hardcoded `0.0` | DEFAULT | Window-level statistic; not computable per-row |
| 36 | `dst_host_srv_diff_host_rate` | Fraction of connections to different hosts for same service | Hardcoded `0.0` | DEFAULT | Window-level statistic; not computable per-row |
| 37 | `dst_host_serror_rate` | Fraction of connections to same host with SYN errors (100-connection window) | Hardcoded `0.0` | DEFAULT | Window-level statistic; not computable per-row |
| 38 | `dst_host_srv_serror_rate` | Fraction of connections to same service/host with SYN errors | Hardcoded `0.0` | DEFAULT | Window-level statistic; not computable per-row |
| 39 | `dst_host_rerror_rate` | Fraction of connections to same host with REJ errors (100-connection window) | Hardcoded `0.0` | DEFAULT | Window-level statistic; not computable per-row |
| 40 | `dst_host_srv_rerror_rate` | Fraction of connections to same service/host with REJ errors | Hardcoded `0.0` | DEFAULT | Window-level statistic; not computable per-row |

---

## Summary

| Status | Count |
|---|---|
| DIRECT | 6 |
| DERIVED | 2 |
| DEFAULT | 32 |
| UNAVAILABLE | 0 |
| **Total** | **40** |

**DIRECT features (6):** `duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes`

**DERIVED features (2):** `count` (proxied by `orig_pkts`), `srv_count` (proxied by `resp_pkts`)

**DEFAULT features (32):** All remaining 32 features are hardcoded constants — see table above for individual defaults and rationale.

---

## Limitations for Live-Network Inference

### Distribution Shift Warning

The ML models in this framework (CNN-GRU and Autoencoder) were trained on the
**NSL-KDD dataset**, in which all 40 features contain real, measured values
derived from the original KDD Cup 1999 network simulation environment.

When the models are deployed in a live network via `zeek_capture.py`, **32 of
the 40 features** are set to fixed hardcoded defaults rather than real measured
values. This creates a **distribution shift** between the training data and
live inference inputs:

- The training data had real, varied values for features like `same_srv_rate`,
  `dst_host_count`, `serror_rate`, etc. These values encoded meaningful traffic
  behaviour patterns that the models learned to exploit.
- At inference time, those same features are always `0.0`, `1.0`, or `255` — the
  model receives a fundamentally different input distribution.

### Practical Consequences

1. **Autoencoder (System D):** The autoencoder learns a reconstruction of the
   40-dimensional normal-traffic distribution. Since 32 dimensions are now
   constant at inference time, the effective input dimensionality is reduced to
   8. The reconstruction error may be systematically lower or higher than the
   training distribution, causing the 95th-percentile threshold to be poorly
   calibrated for live inputs.

2. **CNN-GRU (System C):** The classifier trained to distinguish attack classes
   using all 40 features may rely on weight patterns in the 32 defaulted
   dimensions. At inference, those dimensions carry no discriminatory signal,
   degrading classification accuracy in ways that are hard to predict without
   live data.

3. **Window-level features (24–40):** The NSL-KDD dataset computes features
   like `serror_rate`, `dst_host_count`, and `same_srv_rate` over 2-second and
   100-connection rolling windows. These features are specifically designed to
   distinguish attack patterns (e.g., port scans, DoS floods) from normal traffic.
   Defaulting all of them to neutral values (0.0 or 1.0) effectively disables
   a large portion of the detection signal the models were trained on.

### Mitigation Approaches

To reduce distribution shift when deploying against live traffic, consider:

- **Implement a rolling-window aggregator** in `zeek_capture.py` that
  computes the per-connection window statistics (features 24–40) over a
  sliding buffer of recent connections before forwarding to the API.
- **Retrain or fine-tune** the models on Zeek-derived data (using only the
  8 features that can be populated from `conn.log`) so that model expectations
  match the actual inference-time input distribution.
- **Use a separate feature source** such as Zeek's `notice.log`, `http.log`, or
  a custom Zeek script to populate application-layer and window-level features
  that are unavailable in `conn.log` alone.
- **Document this limitation** clearly in any deployment context where
  detection quality guarantees based on NSL-KDD benchmark results are cited.

> **Note:** The startup warning emitted by `zeek_capture.py` at module load
> time is intended to make this limitation visible in production logs.
> See the `logging.warning(...)` call in `src/zeek_capture.py`.
