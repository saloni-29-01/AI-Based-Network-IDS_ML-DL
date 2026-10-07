# Contributing

Thanks for considering a contribution to the **AI-Based Network Intrusion
Detection System**.

- **Repository:** <https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL>
- **Maintainer:** [Saloni Kumari](https://github.com/saloni-29-01)

The project began as a fork of
[mohammedAcheddad/AI-Based-Network-IDS_ML-DL](https://github.com/mohammedAcheddad/AI-Based-Network-IDS_ML-DL)
by Mohammed Ali Cheddad (see [README.md](README.md#credits) for full credit)
and was extended into an integrated IDS in v2.0.

## Ways to contribute

- **Bug reports:** open an issue with the
  [Bug Report template](https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL/issues/new?template=bug_report.md).
  Include your OS, Python version, the mode you were running (Dataset
  Simulation / Flow Replay / PCAP Replay / Live Capture) and the relevant
  lines from `logs/ids.log`.
- **Feature ideas:** open an issue with the
  [Feature Request template](https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL/issues/new?template=feature_request.md).
- **Pull requests:** for anything beyond a small fix, open an issue first so
  the change can be discussed.
- **Security issues:** do **not** open a public issue; follow [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL.git
cd AI-Based-Network-IDS_ML-DL
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
python setup.py                   # folders, database, demo data; trains models if missing
python run.py --open              # dashboard at http://127.0.0.1:8000
```

Python 3.12 is the tested version. Live capture additionally needs Npcap on
Windows (see the README).

## Project layout (where to make changes)

| Area | Location |
|---|---|
| Packet parsing, flow tracking, sources | `app/capture/` |
| NSL-KDD feature schema and flow features | `app/features/` |
| Preprocessing, training, registry, explanations | `app/preprocessing/`, `app/models/` |
| GAN augmentation | `app/gan/` |
| Detection, risk scoring, alerts | `app/detection/`, `app/alerts/` |
| API and WebSocket | `app/api/` |
| Dashboard | `frontend/` |
| Tests | `tests/` |

## Before opening a pull request

1. Run the test suite: `python -m pytest` (all tests must pass).
2. Run the linter: `ruff check app scripts tests`.
3. Add or update tests for behaviour you change.
4. If you retrain models, regenerate the results with
   `python scripts/export_results.py` and never hand-edit metrics.
5. Add a short entry to [CHANGELOG.md](CHANGELOG.md).
6. Keep pull requests focused: one topic per PR is easier to review.

## Ground rules for this project

- **No fabricated results.** Every metric shown in the UI or docs must come
  from an actual evaluation run.
- **Defensive scope only.** Contributions must observe, analyse, classify or
  visualise traffic. Exploit code, attack-traffic generators, credential
  theft or packet injection will not be accepted.
- **Keep the engines separate.** The 41-feature NSL-KDD engine and the
  28-feature flow engine must not be mixed; live traffic must never be fed
  fabricated content features.
- **Preserve attribution** to the original author as required by the MIT License.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you agree to uphold it.
