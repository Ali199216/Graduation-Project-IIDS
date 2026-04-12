import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from config import FEATURES, DATASET_PATH, MODELS_DIR
from preprocessing import clean_features
from evaluate import evaluate_model

df = pd.read_csv(DATASET_PATH)

X = clean_features(df, FEATURES)
y = df["Label"].astype("int8")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

print("Training started")

rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    min_samples_leaf=2,
    max_features="log2",
    n_jobs=-1,
    random_state=42
)

xgb = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.10,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42
)

rf.fit(X_train, y_train)
xgb.fit(X_train, y_train)

joblib.dump(rf, MODELS_DIR / "stage1_rf.pkl")
joblib.dump(xgb, MODELS_DIR / "stage1_xgb.pkl")

print("Stage 1 models trained")

evaluate_model(rf, X_test, y_test, model_name="Random Forest — Stage 1", binary=True)
evaluate_model(xgb, X_test, y_test, model_name="XGBoost — Stage 1", binary=True)