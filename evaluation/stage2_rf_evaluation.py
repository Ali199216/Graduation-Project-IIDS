import pandas as pd
import itertools

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score
)
from sklearn.ensemble import RandomForestClassifier

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import FEATURES, DATASET_PATH
from src.preprocessing import clean_features, encode_multiclass




df = pd.read_csv(DATASET_PATH)
df = df[df["Label"] == 1].copy()

X = clean_features(df, FEATURES)
y, encoder = encode_multiclass(df["Attack"])

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)


param_grid = {
    "n_estimators": [200, 400],
    "max_depth": [15, 25],
    "min_samples_leaf": [1, 5],
}

results = []


for values in itertools.product(*param_grid.values()):
    params = dict(zip(param_grid.keys(), values))
    print(f"Training RF Stage 2 with parameters: {params}")

    model = RandomForestClassifier(
        **params,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    results.append({
        **params,
        "f1_macro": f1_score(y_test, y_pred, average="macro"),
        "accuracy": accuracy_score(y_test, y_pred),
        "precision_macro": precision_score(y_test, y_pred, average="macro", zero_division=0),
        "recall_macro": recall_score(y_test, y_pred, average="macro", zero_division=0),
    })


results_df = pd.DataFrame(results)
results_df.sort_values("f1_macro", ascending=False, inplace=True)

results_df.to_csv(
    "results/stage2_rf_hyperparameter_results.csv",
    index=False
)

print("\nStage 2 Random Forest hyperparameter search complete.")
print(results_df)