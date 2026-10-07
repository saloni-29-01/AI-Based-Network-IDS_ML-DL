# Implementation status

Verified on Linux (Python 3.12.x, TensorFlow 2.21, scikit-learn 1.9.1, Scapy 2.8)
on 2026-10-07. "Verified" means it was run and the result checked, not just written.
Windows was **not** available in the build environment; see the last section.

| Feature | Status | Verified | How it was verified |
|---|---|---|---|
| NSL-KDD preprocessing | Done | ✅ | tests: train/test consistency, scaler fitted on train only, unknown categories ignored |
| Binary ML | Done | ✅ | 7 binary models per feature set trained and evaluated on KDDTest+ / KDDTest-21 |
| Multiclass ML | Done | ✅ | 7 multiclass models per feature set; per-class metrics and confusion matrices |
| CNN | Done | ✅ | 1D-CNN trained for all 4 task/feature combinations (early stopping) |
| Ensemble | Done | ✅ | RF 0.6 + CNN 0.4 soft voting, evaluated from members' actual predictions |
| Model registry / versioning | Done | ✅ | metadata per version; GAN retrain created `v2` of the `-gan` entries; models cached (test) |
| GAN | Done | ✅ | conditional WGAN-GP, 60 epochs; validation; retrain comparison (U2R recall 1.5% → 25.4%); 5 GAN tests |
| Explainability | Done | ✅ | tree path attribution: `bias + Σ contributions = P(class)` to 1e-9 (test); global importance |
| Live capture | Done | ✅ (Linux) | real HTTP traffic sniffed on `lo`: 15 requests → exactly 15 SF flows, correct byte counts |
| Flow extraction | Done | ✅ | TCP state machine (SF/S0/REJ/RSTO/OTH), UDP/ICMP pairing, KDD 2 s and host-window features (tests) |
| Detection engine | Done | ✅ | full and flow engines; validation rejects bad records; p95 latency ≈ 170 ms under load |
| Risk engine | Done | ✅ | verdicts, levels, factors, bounded score (tests) |
| Alerts | Done | ✅ | dedup, rate limit, status workflow, lazy explanation (tests + UI) |
| Database | Done | ✅ | SQLite WAL; events / alerts / model_runs / system_events (tests) |
| API | Done | ✅ | every endpoint group exercised through FastAPI TestClient (tests) |
| WebSocket | Done | ✅ | `/ws/live` hello + update frames (test); dashboard live updates (headless browser) |
| Dashboard | Done | ✅ | 8 pages rendered in headless Chromium; no console errors; dark, light and 390 px mobile layouts |
| PCAP replay | Done | ✅ | 6,099-packet benign capture → 572 flows, 0 false positives; pause/resume/speed via API |
| Flow replay | Done | ✅ | 1,499 NSL-KDD flow records; running accuracy ≈ 77% vs ground truth |
| Dataset simulation | Done | ✅ | KDDTest+ replay; running accuracy ≈ 75% matches offline evaluation |
| One-click demo | Done | ✅ | `POST /api/demo/start` and the dashboard button (headless browser) |
| Drift monitoring | Done (basic) | ✅ | PSI on predicted-class distribution + unseen/out-of-range rates |
| Exports / report | Done | ✅ | alerts CSV, events CSV, HTML report (tests) |
| Tests | Done | ✅ | **54 passed** (`python -m pytest`), also 51/51 on the author's Windows 11 laptop |
| Documentation | Done | ✅ | README, ARCHITECTURE, AUDIT, RESULTS (generated), VIVA_GUIDE, CHANGELOG |
| `run_project.bat` | Done | ⚠️ not executed | written for cmd.exe with CRLF endings; its helper `scripts/api_call.py` was tested on Linux |
| Windows 11 run | Done | ✅ | author's laptop: setup, all modes, dashboard pages and 51/51 tests matched the Linux results |
| Windows live capture (Npcap) | Done | ✅ | Npcap 1.89 on Windows 11, Realtek Wi-Fi adapter: ~1,700 pkt/s captured, flows built and scored live |
| PostgreSQL | Not implemented | — | SQLite only; would need an SQLAlchemy layer (documented) |

## Issues found during verification and fixed

1. **PCAP link-type detection.** The first `PcapReader` in a process read Ethernet frames as Raw (Scapy registers layers lazily), so replay produced 0 packets. Fixed by importing layers eagerly, with an Ethernet re-dissection fallback.
2. **Detection throughput.** Per-attack explanations cost about 23–31 ms each, so the queue backed up (p95 latency 8.4 s). Fixed by computing explanations only for new alerts and replacing sklearn calls with a direct tree walk (0.8 ms, identical output). p95 is now ≈ 170 ms.
3. **GAN numeric collapse.** tanh was applied twice, capping outputs at ±0.76, so every synthetic `duration` was 3 and every `hot` was 1, and augmentation had no effect. Fixed (single tanh, class-balanced batches); the final Wasserstein estimate fell from 1.49 to 0.15. A regression test fails if the bug returns. The models from the buggy run (`*-gan` v1) were discarded; `v2` is the corrected run.
4. **Loopback double counting.** On Linux `lo`, raw sockets see each frame twice, which doubled byte counts. Fixed by dropping byte-identical frames within 2 ms (counted in the source progress). Covered by tests.
5. **BPF without libpcap.** Linux without libpcap cannot compile kernel filters. Capture now falls back to unfiltered capture with a visible note.
6. **Excessive GAN volume.** Auto-targets would have inflated U2R from 52 to ~33,600 rows. Capped at min(20× real, 25% of majority).

## Live-traffic finding: broadcast/multicast false positives

On a real campus Wi-Fi network the flow engine labelled most broadcast/multicast discovery traffic (SSDP to 239.255.255.250, NetBIOS/DHCP to x.x.255.255) as **Probe**: many hosts contacting one destination on varied ports looks like a scan in NSL-KDD's feature space, and NSL-KDD contains no such traffic. Such flows are now **counted but not scored** (`SKIP_BROADCAST=true`, shown on the dashboard as "broadcast/multicast not scored"); unicast traffic is still scored. This is the dataset-domain limitation observed directly, and is covered by tests.

## What still needs a Windows machine

* Running `run_project.bat` end to end (menu, venv detection, server window).
* Live capture with Npcap: interface names on Windows look like `\Device\NPF_{GUID}`; the dashboard lists them with descriptions.
* TensorFlow on Windows uses the CPU build (no extra steps for Python 3.12). If it fails to import, CNN and GAN are reported as unavailable and the classical models keep working.
