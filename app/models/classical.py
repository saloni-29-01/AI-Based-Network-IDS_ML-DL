"""Classical ML model factories (the same algorithm set the original
project evaluated: Logistic Regression, Naive Bayes, SVM, Decision Tree,
Random Forest)."""
from __future__ import annotations

from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

ALGORITHMS = {
    "lr": "Logistic Regression",
    "nb": "Naive Bayes",
    "svm": "Linear SVM (calibrated)",
    "dt": "Decision Tree",
    "rf": "Random Forest",
    "cnn": "1D-CNN",
}


def build_classical(algo: str, seed: int = 42):
    if algo == "lr":
        return LogisticRegression(max_iter=2000)
    if algo == "nb":
        return GaussianNB()
    if algo == "svm":
        # LinearSVC has no predict_proba; Platt-style calibration supplies
        # probabilities so the SVM can feed the risk engine and ROC-AUC.
        return CalibratedClassifierCV(LinearSVC(dual=False, C=1.0, max_iter=5000), cv=3)
    if algo == "dt":
        return DecisionTreeClassifier(random_state=seed, min_samples_leaf=1)
    if algo == "rf":
        return RandomForestClassifier(n_estimators=100, min_samples_leaf=2,
                                      n_jobs=-1, random_state=seed)
    raise ValueError(f"not a classical algorithm: {algo}")
