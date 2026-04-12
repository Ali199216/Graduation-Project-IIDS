import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)
from sklearn.ensemble import RandomForestClassifier
import itertools

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import FEATURES, DATASET_PATH
from src.preprocessing import clean_features

df = pd.read_csv(DATASET_PATH)

y = df["Label"].astype(int)
X = clean_features(df, FEATURES)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

param_grid = {
    "n_estimators": [100, 300],
    "max_depth": [None, 30],
    "min_samples_leaf": [2, 10],
    "max_features": ["sqrt", "log2"],
}


results = []

for params in itertools.product(*param_grid.values()):
    config = dict(zip(param_grid.keys(), params))

    model = RandomForestClassifier(
        **config,
        class_weight="balanced",
        max_samples=0.7,
        n_jobs=-1,
        random_state=42,
    )

    print(f"Training with parameters: {config}")

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    results.append({
        **config,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1": f1_score(y_test, y_pred, zero_division=0),
    })

results_df = pd.DataFrame(results)
results_df.sort_values("f1", ascending=False, inplace=True)

results_df.to_csv("results/stage1_rf_hyperparameter_results.csv", index=False)

print("\nHyperparameter search complete.")
print(results_df)