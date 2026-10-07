# Changelog

Repository: <https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL>  
Maintainer: [Saloni Kumari](https://github.com/saloni-29-01)

All notable changes to this project are documented here. The format follows

(MIT License, © 2025 Mohammed Ali Cheddad) — see [README.md](README.md)
for full attribution.

Every change below was made against the actual project code and, where the
change touched the data pipeline, was re-run against the real NSL-KDD
files to confirm it still executes correctly (TensorFlow/CNN training
cells could not be executed in the environment used to prepare this
release — see "Reproducing results" in the README).

## [2.0.0] — Integrated IDS system (2026-10-07) — Saloni Kumari

Turns the notebook project into a working intrusion detection system. The
original notebooks, dataset and `script.py` are preserved. Audit findings
are in [docs/AUDIT.md](docs/AUDIT.md); results are in [docs/RESULTS.md](docs/RESULTS.md).

### Added
- `app/` package: configuration (`.env`), structured rotating logs, FastAPI backend, WebSocket live stream.
- Unified training pipeline (`scripts/train_models.py`): LR, NB, calibrated Linear SVM, DT, RF and 1D-CNN for binary and multiclass tasks, on the 41-feature and 28-feature (flow) sets, plus an RF+CNN soft-voting ensemble: 28 registry entries.
- Honest evaluation on KDDTest+ and KDDTest-21, with preprocessing fitted on training data only; validation hold-out; accuracy, P/R/F1, FPR/FNR, ROC-AUC, confusion matrix and per-class metrics written to model metadata.
- Versioned model registry with an in-memory model cache (models load once).
- Flow engine: models trained on the 28 packet-derivable NSL-KDD features; the 13 content features are not fabricated for live traffic.
- Packet layer: Scapy parsing, bidirectional 5-tuple flow tracker with TCP state -> NSL-KDD flag, KDD time-based and host-based traffic features.
- Sources: live capture (Npcap/Administrator detection with clear errors), PCAP replay (pause/resume, 0.5–10x), flow replay of NSL-KDD records, dataset simulation with live ground-truth accuracy.
- Risk engine (configurable severities, transparent factors), alert manager (de-duplication, rate limiting, status workflow, optional webhook), SQLite storage.
- Tree path attribution explanations (exact identity, computed lazily for new alerts) and global feature importance.
- Conditional WGAN-GP augmentation (`app/gan/`) with synthetic-data validation, capped generation, and an RF/CNN retrain comparison.
- Basic drift monitor (PSI on predicted-class distribution, unseen categories, out-of-range values).
- Dashboard with 8 pages, offline canvas charts, dark/light themes and a responsive layout; CSV exports and an HTML report.
- `setup.py`, `run.py`, `run_project.bat` menu, `scripts/api_call.py`; benign demo PCAP generator; `scripts/export_results.py`.
- 54-test pytest suite; `docs/ARCHITECTURE.md`, `docs/AUDIT.md`, `docs/RESULTS.md`, `docs/IMPLEMENTATION_STATUS.md`.

### Fixed (found while verifying on real traffic and on Windows 11)
- PCAP replay read Ethernet frames as Raw in a fresh process (Scapy lazy layer registration): layers now imported eagerly, with a re-dissection fallback.
- Detection throughput: explanations computed only for new alerts and via a direct tree walk (~40x faster, identical output); p95 latency 8.4 s -> ~0.2 s.
- GAN numeric collapse caused by a double `tanh`; fixed together with class-balanced batch sampling (U2R recall after augmentation 1.5% -> 25.4%).
- Linux loopback duplicate frames doubled byte counts in live capture; byte-identical frames within 2 ms are now dropped and counted.
- BPF filter without libpcap: capture falls back to unfiltered mode with a visible note.
- Live Wi-Fi: broadcast/multicast discovery traffic (SSDP, NetBIOS, DHCP) was labelled Probe; it is now counted but not scored (`SKIP_BROADCAST`).
- A *Suspicious* (uncertain) verdict is capped at MEDIUM risk so it never outranks a confident detection.
- Model-comparison chart title now matches what it plots.

### Verified
- Windows 11 + Python 3.12.10 + Npcap 1.89: setup, all four modes, every dashboard page, live capture on a Wi-Fi adapter, and the full test suite.

### Changed
- README rewritten; original-author attribution preserved and the original vs added work clearly separated.
- Notebooks: explanatory markdown intro cells added, including the random-split evaluation caveat. Code cells unchanged.
- `script.py`: menu text now matches the number of predefined records; docstring points to the new app.
- `LICENSE`: original copyright notice kept unchanged; a second copyright line for the v2.0 work added (permitted by the MIT License).
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`: repository links, maintainer and contact routes filled in.
- `requirements.txt`: added FastAPI, uvicorn, Scapy, psutil; pinned scikit-learn to match the shipped model artifacts; notebook-only tools moved to `requirements-dev.txt`.

## [1.1.0] — Modernization Pass — Saloni Kumari

### `BinaryPrediction.ipynb`

- **Fixed:** cells that trained Logistic Regression, GaussianNB, Linear
  SVC, Decision Tree, and Random Forest models called a function named
  `evaluate_classification`, which did not exist yet at that point in the
  notebook (it was only defined later, as a *different*, neural-network
  specific function). Running the notebook top-to-bottom raised
  `NameError`. **Fix:** these cells now call `evaluate_classification_RF`,
  the classical-ML evaluator that was already defined earlier in the
  notebook for exactly this purpose.
  *Compatibility issue fixed:* broken execution order. *Code quality:*
  restores a working, linear notebook flow.
- **Fixed (correctness):** `x_test = scaler.fit_transform(x_test)` was
  re-fitting the `StandardScaler` on the test set instead of reusing the
  scaler fitted on the training set. This is a data-leakage bug — the
  train and test sets ended up on two different scales. Changed to
  `scaler.transform(x_test)`.
  *ML quality:* removes a methodological error that could distort
  reported test performance.
- **Fixed (pandas 3.x compatibility):** the binary-outcome column was
  built by assigning integers into an existing string column via
  `.loc[...] = 0` / `.loc[...] = 1`. Current pandas defaults text columns
  to a strict `StringDtype` that rejects mixed str/int assignment,
  raising `TypeError: Invalid value '0' for dtype 'str'`. Replaced with a
  single-step `np.where(...)` that builds the numeric column directly.
  *Compatibility issue fixed:* the notebook would not run at all under
  current pandas without this change (confirmed against the real dataset).
- **Updated (deprecated API):** `tensorflow.keras.wrappers.scikit_learn.KerasClassifier`
  (removed from TensorFlow 2.11+) replaced with `scikeras.wrappers.KerasClassifier`,
  including the `model__`-prefixed hyperparameter grid SciKeras expects.
- **Updated (Keras 3 style):** `Dense(..., input_shape=(...))` on the
  first layer replaced with an explicit `Input(shape=(...))` layer, in
  both the main CNN model and the `build_model` function used for
  `RandomizedSearchCV`.
- **Updated (portability):** hyperparameter search training was hardcoded
  to `tf.device('/GPU:0')`, which fails on any machine without a GPU.
  Changed to detect GPU availability and fall back to CPU automatically.
- **Cleaned up:** removed unused imports (`xgboost`, `sklearn.tree`,
  `KNeighborsClassifier`, `RandomForestRegressor`, `OneHotEncoder`,
  `regularizers`) and an unused variable (`dt`, a duplicate Decision Tree
  that was fit but never evaluated — only `tdt` was used downstream).
  Consolidated two overlapping import cells into one.
  *Code quality:* fewer dependencies, no dead code.

### `MulticlassPrediction.ipynb`

- **Fixed (correctness — label alignment):** the multi-class label
  encoder (`LabelEncoder`) was fit *twice*, independently — once on the
  training labels, once on the test labels. Two independently-fit
  encoders can assign different integer codes to the same class (e.g.
  `"Dos" → 0` in train but `"Dos" → 2` in test), silently corrupting every
  downstream comparison between predictions and ground truth. Fixed by
  fitting the encoder once on the training labels and reusing it
  (`.transform`, not `.fit_transform`) on the test labels. Verified
  against the real dataset that both splits now share the same code space
  (`['Dos', 'Probe', 'R2L', 'U2R', 'normal']`).
- **Fixed (correctness — label alignment):** the same issue existed for
  `LabelBinarizer` (used to one-hot encode the CNN's target). Fixed by
  fitting one binarizer on the training labels and reusing it for the
  test labels.
- **Fixed (correctness — feature scaling / leakage):** the
  `standardization()` helper fit a *new* `StandardScaler` per column,
  and was called separately (and independently) on the training and test
  sets — meaning the two sets were standardized using two different sets
  of statistics. Rewrote as `fit_standardization()` (fits and stores one
  scaler per column, using the training data) and `apply_standardization()`
  (replays those exact fitted scalers on the test data).
- **Fixed (correctness — mismatched feature count):** after one-hot
  encoding, the code dropped columns present in train but missing from
  test, but never handled the reverse case — columns present in test but
  missing from train. This left the two feature matrices with a different
  number of columns (confirmed against the real data: 113 vs. 114
  columns), which would crash the model at prediction time. Fixed to
  reconcile the column sets in both directions.
- **Fixed (correctness — variable collision):** the one-hot-encoded
  target array was assigned back into the same variable name
  (`y_train_multi`) that the Random Forest baseline, much later in the
  notebook, expected to still hold the *integer-coded* labels. Running
  the notebook top-to-bottom would have trained the Random Forest on
  one-hot targets and then crashed at `le2.inverse_transform()` on its
  one-hot predictions. Fixed by giving the one-hot arrays their own names
  (`y_train_multi_ohe` / `y_test_multi_ohe`), leaving `y_train_multi` /
  `y_test_multi` as the integer-coded columns the Random Forest section
  actually needs.
- **Fixed (correctness — mislabeled report/confusion matrix):** two
  different hardcoded `classes = [...]` lists were used for the deep
  learning classification report and the Random Forest confusion matrix —
  and neither matched the actual order `LabelEncoder` assigns
  (alphabetical: `Dos, Probe, R2L, U2R, normal`). This silently mislabeled
  the rows/columns of both outputs. Both now derive `classes` from
  `le2.classes_` directly.
- **Updated (deprecated APIs):** `tf.config.experimental.list_physical_devices`
  and `tf.test.is_gpu_available()` (both deprecated/removed in current
  TensorFlow) replaced with `tf.config.list_physical_devices('GPU')`.
- **Updated (Keras 3 style):** `Conv1D(..., input_shape=(...))` replaced
  with an explicit `Input(shape=(...))` layer.
- **Updated (portability):** hardcoded `tf.device('/GPU:0')` for CNN
  training replaced with automatic GPU/CPU fallback.
- **Fixed (dangling reference):** a display-only cell referenced a
  variable name (`data_test`) that no longer existed after the
  standardization fix above; updated to display `multi_data_test`.
- **Cleaned up:** removed unused imports (`pickle`, `os.path`,
  `OrdinalEncoder`, `MinMaxScaler`, `OneHotEncoder`, `Normalizer`,
  `MaxAbsScaler`, `PowerTransformer`, `keras.models.Model`,
  `keras.utils.vis_utils.plot_model`, `RandomForestRegressor`,
  `accuracy_score`, `precision_score`, `recall_score`, `f1_score`);
  standardized all Keras imports to `tensorflow.keras.*` (the original
  mixed bare `keras.*` and `tensorflow.keras.*` imports); removed a
  duplicate `model.evaluate(...)` call; consolidated imports into one
  cell.
- **Documentation:** the notebook previously had no markdown cells at
  all. Added section headers (Imports, Label Consolidation, EDA,
  Preprocessing, Feature Standardization, Label/One-Hot Encoding,
  Train/Test Split, CNN Model, Reporting Helpers, Random Forest Baseline)
  for readability.

### `script.py`

- **Cleaned up:** removed unused imports (`numpy`, `StandardScaler`,
  `PCA`, `confusion_matrix` were imported but never referenced).
- **Documentation:** added a module docstring and type-hinted, documented
  docstrings for `preprocess()`, `train_and_save_model()`, and
  `predict()`, clarifying that train-time fits a new encoder/scaler while
  inference-time only transforms with the saved ones (this file did not
  have the leakage bug found in the notebooks — it was already written
  correctly).
- No behavioral changes; re-verified end-to-end (train → save → load →
  predict) against the real NSL-KDD data after the edits.

### Project-level

- **Added:** `requirements.txt` and `requirements-dev.txt` with current,
  compatible dependency floors (Python 3.12+, TensorFlow 2.16+/Keras 3+,
  current NumPy/Pandas/scikit-learn, SciKeras).
- **Added:** `.gitignore` covering Python/Jupyter artifacts, trained
  model files (`*.pkl`, `*.h5`, `*.keras`), and TensorBoard logs.
- **Added:** this `CHANGELOG.md`.
- **Rewrote:** `README.md` — see the README itself for what changed;
  original authorship, license, and citation information are preserved
  in full (MIT License requires the copyright/permission notice to
  remain, and it does).
- **Filled in:** `CONTRIBUTING.md` and `SECURITY.md`, which were
  placeholder `TODO` stubs in the original project.
- **Unchanged in 1.1.0:** `LICENSE`, `CODE_OF_CONDUCT.md`,
  `.github/ISSUE_TEMPLATE/*` and the `nsl-kdd/` dataset files. (In 2.0.0 the
  LICENSE gained a second copyright line; the original notice is untouched.)

## [1.0.0] — Original project

Original implementation by Mohammed Ali Cheddad:
<https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL>
(Zenodo DOI [10.5281/zenodo.17488850](https://doi.org/10.5281/zenodo.17488850)).

[2.0.0]: https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL
[1.0.0]: https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL