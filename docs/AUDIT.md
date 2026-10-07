# Repository audit (before the v2.0 rebuild)

This audit was done on the modernised fork as received, before any v2.0 code
was written. It records what existed, what was reused, and the defects that
shaped the new architecture.

## What existed

| Item | State |
|---|---|
| `nsl-kdd/` | Complete NSL-KDD: KDDTrain+ (125,973 rows), KDDTrain+_20Percent, KDDTest+ (22,544), KDDTest-21 (11,850), `.txt` + `.arff`. Labels map cleanly to 4 attack categories + normal. |
| `BinaryPrediction.ipynb` | LR, GaussianNB, LinearSVC, Decision Tree, Random Forest, a Keras network and a RandomizedSearchCV over it. |
| `MulticlassPrediction.ipynb` | Label consolidation, per-column standardisation, one-hot encoding, a Conv1D CNN, RF baseline, ROC/AUC and confusion-matrix plots. |
| `script.py` | CLI: trains RF + DT (binary) on KDDTrain+, pickles them, and classifies 7 hard-coded records from a menu. |
| Docs | README (with original-author attribution), CHANGELOG, SECURITY, CONTRIBUTING, MIT LICENSE. |

There was **no live IDS**: no packet capture, no flow features, no API, no
persistence, no alerting and no dashboard.

## Defects and risks found

1. **Optimistic binary evaluation.** `BinaryPrediction.ipynb` evaluates on a
   random 80/20 split *inside KDDTrain+*. KDDTest+ contains attack types that
   never appear in training, so the ~99% figures in the README do not measure
   generalisation. v2.0 evaluates every model on the official KDDTest+ and
   KDDTest-21 splits (≈75–82% accuracy, consistent with published NSL-KDD results).
2. **Leakage in binary preprocessing.** The notebook's `preprocess()` fits the
   `RobustScaler` on the whole dataset before `train_test_split`, and PCA is
   also fitted before the split. v2.0 fits all preprocessing on the training
   portion only (`app/preprocessing/pipeline.py`, covered by a test).
3. **"CNN" in the binary notebook is a dense MLP** (Dense-Dense-Dense). Only
   the multiclass notebook contains convolutional layers. v2.0's `app/models/cnn.py`
   is a real 1D-CNN (refactored from the multiclass architecture) and is used for both tasks.
4. **Mislabelled multiclass results table in the README.** The support column
   (e.g. "U2R: 9711") matches the *normal* class count of KDDTest+; the
   original author's class order was shifted. v2.0's tables are generated from
   the encoder's actual class order.
5. **Train/test one-hot alignment by column dropping** (`pd.get_dummies` run
   separately on each split). Works only by luck of column order; v2.0 uses a
   single `OneHotEncoder(handle_unknown="ignore")` fitted on training data.
6. **`script.py`**: reloads every pickle on each prediction, writes pickles to
   the current working directory, evaluates on a split of the training file,
   uses a depth-3 tree, and its menu says "1–10" while offering 7 records.
   Kept for backward compatibility (menu text fixed); the application uses
   `app/models/model_registry.py`, which loads each model once.
7. **Class imbalance.** U2R has 52 training rows and R2L 995 (vs 67,343
   normal). Multiclass recall for these classes is very low, which motivated
   the GAN augmentation experiment.
8. **No path from packets to NSL-KDD features.** 13 of the 41 features
   (`hot`, `num_failed_logins`, `logged_in`, `root_shell`, …) need payload/
   session inspection and cannot be computed from packet headers. Feeding
   zeros for them into a 41-feature model would be scientifically invalid.

## Architectural decisions that follow from the audit

* **Two detection engines, never mixed:** a 41-feature engine for NSL-KDD
  records (dataset simulation) and a 28-feature *flow* engine, trained only
  on the header-derivable features, for PCAP replay and live capture. The UI
  always shows which engine is running.
* **Official test splits** for every reported metric; metrics are written to
  model metadata by the training run and never hard-coded.
* **Notebooks preserved** for research/reference; production code lives in
  `app/` modules.
* **Demo traffic without attack generation.** The bundled PCAP is benign
  traffic only. Attack-shaped examples for the flow engine come from the
  genuine NSL-KDD records (Flow Replay), not from synthesised attack packets.
