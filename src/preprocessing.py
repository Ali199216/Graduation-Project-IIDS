import numpy as np
from sklearn.preprocessing import LabelEncoder

def clean_features(df, features):
    X = df[features].replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    X = X.clip(-1e9, 1e9)
    return X.astype(np.float32)

def encode_multiclass(labels):
    encoder = LabelEncoder()
    y = encoder.fit_transform(labels)
    return y, encoder