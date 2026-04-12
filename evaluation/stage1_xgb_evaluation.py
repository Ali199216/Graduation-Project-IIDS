import os
import pandas as pd
import itertools
import xgboost as xgb

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    f1_score,
    precision_score,
    recall_score
)

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import FEATURES, DATASET_PATH
from src.preprocessing import clean_features


os.makedirs("results", exist_ok=True)


df = pd.read_csv(DATASET_PATH)

y = df["Label"].astype(int)
X = clean_features(df, FEATURES)

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)


scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()


param_grid = {
    "n_estimators": [150, 300],
    "max_depth": [4, 6],
    "learning_rate": [0.05, 0.1],
    "subsample": [0.8],
    "colsample_bytree": [0.8],
}

results = []

for values in itertools.product(*param_grid.values()):
    params = dict(zip(param_grid.keys(), values))

    model = xgb.XGBClassifier(
        objective="binary:logistic",
        eval_metric="aucpr",
        scale_pos_weight=scale_pos_weight,
        n_jobs=-1,
        random_state=42,
        **params
    )

    print(f"Training with parameters: {params}")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    result = {
        **params,
        "f1": f1_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
    }

    results.append(result)


results_df = pd.DataFrame(results)
results_df.sort_values("f1", ascending=False, inplace=True)
results_df.to_csv("results/stage1_xgb_hyperparameter_results.csv", index=False)

print("\nHyperparameter search complete.")
print(results_df)