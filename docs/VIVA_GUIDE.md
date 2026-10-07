# Viva guide — short, honest answers

**Why NSL-KDD?**
It is the standard public benchmark for ML-based intrusion detection. It
fixes KDD'99's duplicate records, has a fixed train/test split, and its test set
contains attack types absent from training, so it measures generalisation.
Because it is widely used, results can be compared with the literature. Its
weakness is age: the traffic dates from 1998.

**Why a GAN?**
U2R has 52 training rows and R2L 995, against 67,343 normal. Models
almost never predict these classes. Oversampling (copying rows) adds no new
information. A *conditional* GAN learns the joint distribution of all 41
features and can generate new, plausible minority samples on request. I used
WGAN-GP because its gradient penalty keeps training stable on tabular data, and
I validate every synthetic row (ranges, duplicates, distribution distance)
before it is used. I also cap the volume at 20× the real count so the model
doesn't simply learn the GAN's artefacts. The measured effect on test
recall is reported as it came out, including where it did not help.

**Why Random Forest?**
It is strong on tabular data with mixed feature types, needs little tuning,
handles non-linear interactions and is robust to scaling. It also provides
feature importance and exact per-prediction explanations (path attribution),
which the dashboard uses. It is fast at inference, which matters for live traffic.

**Why a CNN?**
A 1D convolution over the encoded feature vector learns local combinations of
features, a different inductive bias from trees. Its errors differ from the
forest's, which is why the soft-voting ensemble (RF 0.6 + CNN 0.4) is a
reasonable combination. It also covers the deep-learning part of the
original project. The architecture is refactored from the original notebook.

**Why multiclass?**
"Attack or not" is not enough for response: a DoS needs rate limiting, a probe
is reconnaissance, R2L/U2R mean access attempts. The class drives the
severity (U2R/R2L CRITICAL, DoS HIGH, Probe MEDIUM by default) and therefore
how the alert is triaged.

**How does live monitoring work?**
Scapy's sniffer (Npcap on Windows) receives each packet on a background
thread. It is converted to a small `PacketInfo` record and fed to the flow
tracker. The dashboard never waits on capture or inference.

**How are flows generated?**
Packets are grouped by 5-tuple (source/destination IP and port, protocol), with
both directions matched to one flow. For TCP I track SYN, SYN-ACK, FIN and
RST to derive the NSL-KDD connection state (SF, S0, REJ, RSTO, ...). A flow ends
on RST, on FIN from both sides, or on an idle/active timeout. Its features are
then computed: bytes each way, duration, service from the port, and
the KDD traffic statistics over the last 2 seconds and the last 255 connections.

**How are attacks detected?**
The 28 flow features are validated, encoded with the training-fitted
preprocessor, and scored by the flow engine (RF + CNN ensemble). The class with
the highest probability is the prediction; 1 − P(normal) is the attack
probability. If the most likely class isn't normal it is an *Attack*. If the
attack probability is still ≥ 0.35 it is *Suspicious*.

**How are alerts generated?**
The risk engine turns class and confidence into a 0–100 score (class severity ×
confidence, plus points for repetition from one source, sensitive ports and high
connection rate) and lists every factor. Scores ≥ 30 raise an alert. Repeats of
the same source/destination/class within 30 s update one alert (with a count)
instead of flooding the screen, and at most 20 new alerts per second are created.
Explanations are computed only when a new alert is created.

**How does the dashboard receive live data?**
A WebSocket at `/ws/live`. The server pushes a frame twice a second with
status, counters, a per-second time series, new detections and new alerts.
History pages (threat search, alerts, models) use REST endpoints over the
database. All charts come from these numbers; nothing is animated client-side.

**What is the role of the database?**
History and accountability: every scored flow, every alert with its status
changes, every model training run and system events. It is what you filter,
search and export. Real-time counters are kept in memory so the live view
doesn't depend on database speed.

**What is the limitation of NSL-KDD?**
It is old (1998 traffic) and not representative of modern networks or attacks.
13 of its 41 features need payload inspection, so they can't be computed from
packet headers. Random splits of its training file give misleading 99%
accuracy. That is why I report KDDTest+ results, why live detection uses a
separate 28-feature model, and why the dashboard labels live verdicts as indicative.

**What makes this different from a basic ML classifier?**
A classifier scores rows in a notebook. This is a system: four traffic
sources, flow reconstruction and feature engineering from raw packets, two
engines kept scientifically separate, an ensemble, risk scoring, explainable
and de-duplicated alerts, persistence, a live API and dashboard, drift
monitoring, GAN augmentation with validation, and a test suite. It is
also explicit about what it cannot do.

## Two things found and fixed during verification (good viva material)

1. **Live loopback double-counting.** On Linux, a raw socket on `lo` receives
   each frame twice, which doubled byte counts (2,374 instead of 1,187 bytes).
   This was found by checking byte counts against a known 1,000-byte page. Fixed
   by dropping byte-identical frames within 2 ms, counted and reported. Covered by tests.
2. **GAN numeric collapse.** The first GAN run produced constant values
   (every synthetic `duration` = 3, `hot` = 1) because tanh was applied twice,
   capping outputs at ±0.76. This was found by comparing synthetic and real
   feature statistics after augmentation showed no effect. Fixed (single tanh,
   class-balanced batches); the critic's Wasserstein estimate dropped from about
   1.49 to 0.15 (final epoch). With the fix, augmentation raised the Random Forest's
   KDDTest+ recall for U2R from 1.5% to 25.4% and for R2L from 4.4% to 13.0%. Before the fix it changed nothing.
   A regression test now fails if the bug returns.

3. **Broadcast traffic flagged as Probe on live Wi-Fi.** On the college network,
   most live alerts were "Probe" for SSDP multicast (239.255.255.250) and
   broadcast (x.x.255.255) traffic: many hosts contacting one address on
   different ports looks like a scan to a model trained on 1998 data that has no
   such traffic. This is the dataset-domain limitation seen on real traffic.
   Fix: these flows are counted and shown on the dashboard but not scored, and
   unicast traffic is still scored. Tested.
