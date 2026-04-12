import pandas as pd
import joblib
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix

from config import FEATURES, DATASET_PATH, MODELS_DIR
from preprocessing import clean_features
from evaluate import evaluate_model


df = pd.read_csv(DATASET_PATH)

y = df["Label"].astype("int8")

X = clean_features(df, FEATURES)

X_benign = X[y == 0]

contamination_rate = y.mean()

print("Training started")

model = IsolationForest(
    n_estimators=300,
    contamination=0.05,
    max_samples=0.8,
    random_state=42,
    n_jobs=-1
)

model.fit(X_benign)

joblib.dump(model, MODELS_DIR / "stage0.pkl")

print("Isolation Forest trained and saved")

scores = -model.decision_function(X)

threshold = np.percentile(scores, 100 * (1 - contamination_rate))
y_pred = (scores >= threshold).astype(int)

print(f"Anomaly Threshold used: {threshold:.6f}\n")

evaluate_model(model, X, y, model_name="Isolation Forest — Stage 0", binary=True)