# Results

_Generated 2026-10-07 12:40 by `scripts/export_results.py` from the model registry - every figure comes from an actual evaluation run._

Evaluation protocol: train on KDDTrain+ (minus a stratified 10% validation hold-out), preprocessing fitted on training data only, test on the official **KDDTest+** split (22,544 records, includes attack types unseen in training). Multiclass precision/recall/F1 are macro averages; FPR = normal traffic flagged as any attack.

Dataset fingerprint: `NSL-KDD[train:ed26fb8417ba,test:b17c8794784e]`  
Preprocessing: `pp-2.0 (onehot+log1p+standard)`

## Binary classification (normal vs attack) — KDDTest+

| Model | Features | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|---:|
| 1D-CNN | flow (28) | 81.02% | 92.92% | 72.15% | **81.23%** | 7.26% | 0.961 |
| Decision Tree | flow (28) | 78.99% | 96.23% | 65.67% | **78.06%** | 3.40% | 0.815 |
| Ensemble RF+CNN | flow (28) | 81.52% | 96.98% | 69.71% | **81.11%** | 2.87% | 0.963 |
| Logistic Regression | flow (28) | 75.35% | 91.30% | 62.67% | **74.32%** | 7.89% | 0.793 |
| Naive Bayes | flow (28) | 56.56% | 98.04% | 24.17% | **38.78%** | 0.64% | 0.619 |
| Random Forest | flow (28) | 78.05% | 96.86% | 63.50% | **76.71%** | 2.72% | 0.965 |
| Linear SVM | flow (28) | 75.40% | 91.32% | 62.76% | **74.39%** | 7.89% | 0.786 |
| 1D-CNN | full (41) | 79.80% | 92.48% | 70.23% | **79.83%** | 7.55% | 0.955 |
| Decision Tree | full (41) | 81.11% | 96.69% | 69.19% | **80.66%** | 3.13% | 0.830 |
| Ensemble RF+CNN | full (41) | 81.09% | 96.81% | 69.06% | **80.61%** | 3.01% | 0.962 |
| Logistic Regression | full (41) | 74.45% | 91.34% | 60.88% | **73.06%** | 7.63% | 0.796 |
| Naive Bayes | full (41) | 56.73% | 97.91% | 24.51% | **39.21%** | 0.69% | 0.621 |
| Random Forest | full (41) | 75.80% | 96.65% | 59.56% | **73.70%** | 2.73% | 0.966 |
| Linear SVM | full (41) | 74.78% | 91.36% | 61.51% | **73.52%** | 7.69% | 0.786 |

## Multiclass classification (normal / DoS / Probe / R2L / U2R) — KDDTest+

| Model | Features | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|---:|
| 1D-CNN | flow (28) | 78.47% | 63.57% | 53.77% | **55.26%** | 7.75% | 0.937 |
| Decision Tree | flow (28) | 76.38% | 70.38% | 55.73% | **54.91%** | 3.01% | 0.740 |
| Ensemble RF+CNN | flow (28) | 78.71% | 78.85% | 52.33% | **53.73%** | 3.17% | 0.952 |
| Logistic Regression | flow (28) | 74.57% | 69.14% | 50.57% | **50.92%** | 7.67% | 0.922 |
| Naive Bayes | flow (28) | 30.50% | 44.36% | 33.43% | **23.27%** | 62.21% | 0.632 |
| Random Forest | flow (28) | 75.74% | 69.55% | 49.11% | **50.59%** | 2.61% | 0.950 |
| Linear SVM | flow (28) | 73.16% | 51.28% | 47.63% | **46.52%** | 7.59% | 0.879 |
| 1D-CNN | full (41) | 76.91% | 83.42% | 58.19% | **62.06%** | 3.02% | 0.942 |
| Decision Tree | full (41) | 76.37% | 78.19% | 53.69% | **56.16%** | 3.08% | 0.730 |
| Ensemble RF+CNN | full (41) | 76.41% | 88.20% | 54.77% | **58.71%** | 2.70% | 0.952 |
| Logistic Regression | full (41) | 74.01% | 68.66% | 52.19% | **53.14%** | 7.65% | 0.916 |
| Naive Bayes | full (41) | 35.67% | 47.10% | 37.67% | **27.42%** | 63.65% | 0.694 |
| Random Forest | full (41) | 74.60% | 89.22% | 48.18% | **49.05%** | 2.58% | 0.944 |
| Linear SVM | full (41) | 73.43% | 67.34% | 53.25% | **54.76%** | 7.59% | 0.902 |

### Per-class results: Ensemble RF+CNN (multiclass, full features)

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| normal | 66.03% | 97.30% | 78.67% | 9,711 |
| DoS | 96.28% | 79.14% | 86.87% | 7,460 |
| Probe | 87.96% | 66.09% | 75.47% | 2,421 |
| R2L | 96.99% | 8.94% | 16.38% | 2,885 |
| U2R | 93.75% | 22.39% | 36.14% | 67 |

macro-F1 58.71% · weighted-F1 72.94%

### Per-class results: Ensemble RF+CNN (multiclass, flow features)

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| normal | 68.75% | 96.83% | 80.41% | 9,711 |
| DoS | 96.21% | 86.09% | 90.87% | 7,460 |
| Probe | 86.80% | 66.54% | 75.33% | 2,421 |
| R2L | 92.49% | 10.68% | 19.14% | 2,885 |
| U2R | 50.00% | 1.49% | 2.90% | 67 |

macro-F1 53.73% · weighted-F1 75.25%

## Harder subset: KDDTest-21 (records most classifiers get wrong)

| Model | Features | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|---:|
| 1D-CNN | flow (28) | 59.04% | 53.63% | 46.34% | **45.30%** | 34.99% | 0.880 |
| Decision Tree | flow (28) | 55.42% | 62.13% | 50.80% | **45.65%** | 12.87% | 0.700 |
| Ensemble RF+CNN | flow (28) | 59.50% | 70.44% | 48.05% | **45.08%** | 14.31% | 0.881 |
| Logistic Regression | flow (28) | 51.65% | 59.88% | 42.17% | **40.16%** | 34.57% | 0.842 |
| Naive Bayes | flow (28) | 30.65% | 43.44% | 40.30% | **24.46%** | 26.81% | 0.672 |
| Random Forest | flow (28) | 53.90% | 61.24% | 44.25% | **41.08%** | 11.76% | 0.881 |
| Linear SVM | flow (28) | 48.99% | 42.11% | 39.28% | **35.73%** | 34.11% | 0.806 |
| 1D-CNN | full (41) | 56.08% | 74.95% | 53.11% | **52.58%** | 13.57% | 0.878 |
| Decision Tree | full (41) | 55.37% | 70.04% | 48.95% | **47.05%** | 13.29% | 0.691 |
| Ensemble RF+CNN | full (41) | 55.12% | 79.80% | 49.83% | **49.20%** | 12.17% | 0.886 |
| Logistic Regression | full (41) | 50.56% | 59.35% | 43.84% | **42.39%** | 34.48% | 0.830 |
| Naive Bayes | full (41) | 40.79% | 48.23% | 45.98% | **31.85%** | 26.95% | 0.717 |
| Random Forest | full (41) | 51.91% | 81.12% | 43.18% | **39.41%** | 11.66% | 0.881 |
| Linear SVM | full (41) | 49.52% | 58.13% | 44.96% | **44.02%** | 33.97% | 0.808 |

## GAN augmentation (conditional WGAN-GP)

Conditional WGAN-GP (gradient penalty, Gumbel-softmax categorical heads); 60 epochs; 685.8 s on CPU; 16,828 synthetic samples for R2L, U2R.

| Class | Before | After |
|---|---:|---:|
| normal | 67,343 | 67,343 |
| DoS | 45,927 | 45,927 |
| Probe | 11,656 | 11,656 |
| R2L | 995 | 16,835 |
| U2R | 52 | 1,040 |

| Class | Generated | Valid | Kept | Duplicates of real | Internal duplicates | Distribution closeness | Quality |
|---|---:|---:|---:|---:|---:|---:|---:|
| R2L | 20,592 | 20,592 | 15,840 | 1 | 17 | 0.881 | 96.4 |
| U2R | 1,284 | 1,284 | 988 | 0 | 0 | 0.0 | 70.0 |

### Effect on the Random Forest (KDDTest+)

Accuracy 74.60% → 75.86%; macro-F1 49.05% → 58.62%

| Class | Recall baseline | Recall GAN-augmented | Change |
|---|---:|---:|---:|
| normal | 97.40% | 97.30% | -0.1 pp |
| DoS | 77.40% | 77.70% | +0.3 pp |
| Probe | 60.30% | 60.70% | +0.4 pp |
| R2L | 4.40% | 13.00% | +8.6 pp |
| U2R | 1.50% | 25.40% | +23.9 pp |

### Per-class results: Ensemble RF+CNN (multiclass, full features) [gan]

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| normal | 71.57% | 97.13% | 82.41% | 9,711 |
| DoS | 96.16% | 81.50% | 88.22% | 7,460 |
| Probe | 87.05% | 72.74% | 79.25% | 2,421 |
| R2L | 79.59% | 26.90% | 40.21% | 2,885 |
| U2R | 68.18% | 44.78% | 54.05% | 67 |
