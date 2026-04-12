import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from config import FEATURES, DATASET_PATH, MODELS_DIR
from preprocessing import clean_features, encode_multiclass
from evaluate import evaluate_model

df = pd.read_csv(DATASET_PATH)
df = df[df["Label"] == 1]  # only attacks

X = clean_features(df, FEATURES)
y, encoder = encode_multiclass(df["Attack"])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

print("Training started")

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_leaf=1,
    n_jobs=-1,
    random_state=42
)

xgb = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42
)

rf.fit(X_train, y_train)
xgb.fit(X_train, y_train)

joblib.dump((rf, encoder), MODELS_DIR / "stage2_rf.pkl")
joblib.dump((xgb, encoder), MODELS_DIR / "stage2_xgb.pkl")

print("Stage 2 models trained")

evaluate_model(rf, X_test, y_test, model_name="Random Forest — Stage 2", binary=False, encoder=encoder)
evaluate_model(xgb, X_test, y_test, model_name="XGBoost — Stage 2", binary=False, encoder=encoder)